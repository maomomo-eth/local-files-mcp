package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"
)

const defaultMaxBytes int64 = 2 << 20

type project struct {
	root     *os.Root
	maxBytes int64
	readOnly bool
	mu       sync.RWMutex
}

// 路径检查只负责输入格式；真正的目录边界由 os.Root 保证。
func cleanPath(name string) (string, error) {
	if name == "" {
		name = "."
	}
	if !filepath.IsLocal(name) || strings.ContainsRune(name, 0) || strings.Contains(name, `\`) {
		return "", errors.New("路径必须是项目目录内的相对路径")
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return "", errors.New("路径不能包含 ..")
		}
	}
	return filepath.Clean(name), nil
}

type fileOutput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
}

func hash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func readText(root *os.Root, name string, maxBytes int64) ([]byte, error) {
	// 非阻塞打开，避免路径被换成 FIFO 时卡住整个请求。
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("只支持普通文件")
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("文件超过 %d 字节限制", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("文件超过大小限制")
	}
	if !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return nil, errors.New("只支持 UTF-8 文本文件")
	}
	return data, nil
}

func (p *project) read(name string) (fileOutput, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	name, err := cleanPath(name)
	if err != nil {
		return fileOutput{}, err
	}
	data, err := readText(p.root, name, p.maxBytes)
	if err != nil {
		return fileOutput{}, err
	}
	return fileOutput{filepath.ToSlash(name), string(data), hash(data)}, nil
}

type entry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
type listOutput struct {
	Entries   []entry `json:"entries"`
	Truncated bool    `json:"truncated"`
}

func (p *project) list(name string, limit int) (listOutput, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	name, err := cleanPath(name)
	if err != nil {
		return listOutput{}, err
	}
	if limit == 0 {
		limit = 200
	}
	if limit < 1 || limit > 2000 {
		return listOutput{}, errors.New("limit 必须在 1 到 2000 之间")
	}
	f, err := p.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return listOutput{}, err
	}
	defer f.Close()
	items, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return listOutput{}, err
	}
	out := listOutput{Entries: []entry{}, Truncated: len(items) > limit}
	if len(items) > limit {
		items = items[:limit]
	}
	for _, item := range items {
		kind := "file"
		if item.IsDir() {
			kind = "directory"
		} else if item.Type()&os.ModeSymlink != 0 {
			kind = "symlink"
		} else if !item.Type().IsRegular() {
			kind = "special"
		}
		out.Entries = append(out.Entries, entry{item.Name(), kind})
	}
	return out, nil
}

// 写入在目标父目录的句柄中完成，避免父目录被并发替换后临时文件与目标错位。
// 原子替换也避免通过已有硬链接修改项目外的同一 inode。
func (p *project) writeLocked(name, content, expected string) (fileOutput, error) {
	if p.readOnly {
		return fileOutput{}, errors.New("服务处于只读模式")
	}
	name, err := cleanPath(name)
	if err != nil {
		return fileOutput{}, err
	}
	if name == "." {
		return fileOutput{}, errors.New("不能写入项目根目录本身")
	}
	if !utf8.ValidString(content) || strings.ContainsRune(content, 0) || int64(len(content)) > p.maxBytes {
		return fileOutput{}, errors.New("内容必须是大小限制以内的 UTF-8 文本")
	}
	dir, err := p.root.OpenRoot(filepath.Dir(name))
	if err != nil {
		return fileOutput{}, err
	}
	defer dir.Close()
	base := filepath.Base(name)
	mode := fs.FileMode(0600)
	info, err := dir.Lstat(base)
	existing := err == nil
	if err == nil {
		if !info.Mode().IsRegular() {
			return fileOutput{}, errors.New("写入目标必须是普通文件，不能是符号链接")
		}
		old, err := readText(dir, base, p.maxBytes)
		if err != nil {
			return fileOutput{}, err
		}
		if expected == "" || hash(old) != expected {
			return fileOutput{}, errors.New("文件版本不匹配：请先 read_file，再提供返回的 expected_sha256")
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fileOutput{}, err
	} else if expected != "" {
		return fileOutput{}, errors.New("文件已不存在，请重新读取")
	}
	tmp := ".local-files-mcp-" + rand.Text()
	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fileOutput{}, err
	}
	defer dir.Remove(tmp)
	_, err = f.WriteString(content)
	if err == nil && existing {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fileOutput{}, err
	}
	if closeErr != nil {
		return fileOutput{}, closeErr
	}
	if err = dir.Rename(tmp, base); err != nil {
		return fileOutput{}, err
	}
	return fileOutput{filepath.ToSlash(name), content, hash([]byte(content))}, nil
}

func (p *project) write(name, content, expected string) (fileOutput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.writeLocked(name, content, expected)
}

func (p *project) edit(name, oldText, newText, expected string, replaceAll bool) (fileOutput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	name, err := cleanPath(name)
	if err != nil {
		return fileOutput{}, err
	}
	if p.readOnly {
		return fileOutput{}, errors.New("服务处于只读模式")
	}
	if !utf8.ValidString(oldText) || !utf8.ValidString(newText) || strings.ContainsRune(oldText, 0) || strings.ContainsRune(newText, 0) {
		return fileOutput{}, errors.New("替换内容必须是 UTF-8 文本")
	}
	if oldText == "" {
		return fileOutput{}, errors.New("old_text 不能为空")
	}
	data, err := readText(p.root, name, p.maxBytes)
	if err != nil {
		return fileOutput{}, err
	}
	if expected == "" || hash(data) != expected {
		return fileOutput{}, errors.New("文件版本不匹配：请重新读取")
	}
	count := strings.Count(string(data), oldText)
	if count == 0 || (count > 1 && !replaceAll) {
		return fileOutput{}, fmt.Errorf("old_text 匹配 %d 次；必须唯一匹配或设置 replace_all", count)
	}
	// 先做除法边界检查，避免乘法溢出或 ReplaceAll 分配巨量内存。
	base := int64(len(data)) - int64(count)*int64(len(oldText))
	if base > p.maxBytes || (len(newText) > 0 && int64(count) > (p.maxBytes-base)/int64(len(newText))) {
		return fileOutput{}, errors.New("替换结果超过文件大小限制")
	}
	return p.writeLocked(name, strings.ReplaceAll(string(data), oldText, newText), expected)
}

func (p *project) mkdir(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readOnly {
		return errors.New("服务处于只读模式")
	}
	name, err := cleanPath(name)
	if err != nil {
		return err
	}
	return p.root.MkdirAll(name, 0755)
}

type match struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}
type searchOutput struct {
	Matches   []match `json:"matches"`
	Truncated bool    `json:"truncated"`
	Skipped   int     `json:"skipped"`
}

func (p *project) search(ctx context.Context, name, query string, limit int) (searchOutput, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := searchOutput{Matches: []match{}}
	name, err := cleanPath(name)
	if err != nil {
		return out, err
	}
	if query == "" {
		return out, errors.New("query 不能为空")
	}
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 1000 {
		return out, errors.New("limit 必须在 1 到 1000 之间")
	}
	visited := 0
	var bytesRead int64
	var walk func(*os.Root, string, string) error
	walk = func(root *os.Root, local, path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visited >= 20000 || bytesRead >= 32<<20 {
			out.Truncated = true
			return fs.SkipAll
		}
		visited++
		info, err := root.Lstat(local)
		if err != nil {
			out.Skipped++
			return err
		}
		if info.IsDir() {
			// 每次只分配一批目录项，不跟随目录符号链接。
			f, err := root.OpenFile(local, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				out.Skipped++
				return err
			}
			defer f.Close()
			// 从已验证且固定的目录句柄建立子 Root，避免再次解析可被替换的路径。
			child, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
			if err != nil {
				return err
			}
			defer child.Close()
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				items, readErr := f.ReadDir(128)
				for _, item := range items {
					err := walk(child, item.Name(), filepath.ToSlash(filepath.Join(path, item.Name())))
					if errors.Is(err, fs.SkipAll) {
						return err
					}
					if ctx.Err() != nil {
						return ctx.Err()
					}
				}
				if errors.Is(readErr, io.EOF) {
					return nil
				}
				if readErr != nil {
					out.Skipped++
					return readErr
				}
			}
		}
		if path == filepath.ToSlash(name) && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("搜索起点不能是符号链接")
		}
		if !info.Mode().IsRegular() {
			out.Skipped++
			return nil
		}
		f, err := root.OpenFile(local, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			out.Skipped++
			return nil
		}
		defer f.Close()
		actual, err := f.Stat()
		if err != nil || !actual.Mode().IsRegular() {
			out.Skipped++
			return nil
		}
		remaining := int64(32<<20) - bytesRead
		readLimit := min(p.maxBytes+1, remaining)
		data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: f}, readLimit))
		bytesRead += int64(len(data))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || int64(len(data)) > p.maxBytes || actual.Size() > int64(len(data)) || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			out.Skipped++
			if bytesRead >= 32<<20 {
				out.Truncated = true
				return fs.SkipAll
			}
			return nil
		}
		i := 0
		for line := range strings.SplitSeq(string(data), "\n") {
			if err := ctx.Err(); err != nil {
				return err
			}
			i++
			if strings.Contains(line, query) {
				if len(out.Matches) >= limit {
					out.Truncated = true
					return fs.SkipAll
				}
				// 控制单行输出大小，并保持 UTF-8 有效。
				if len(line) > 2000 {
					line = line[:2000]
					for !utf8.ValidString(line) {
						line = line[:len(line)-1]
					}
					line += "…"
				}
				out.Matches = append(out.Matches, match{path, i, line})
			}
		}
		return nil
	}
	err = walk(p.root, name, filepath.ToSlash(name))
	if errors.Is(err, fs.SkipAll) {
		err = nil
	}

	return out, err
}

// 每次底层读取前检查取消，及时释放搜索锁。
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
