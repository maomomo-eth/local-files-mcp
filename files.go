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
	mode := fs.FileMode(0644)
	info, err := dir.Lstat(base)
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
	if err == nil {
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
	if oldText == "" {
		return fileOutput{}, errors.New("old_text 不能为空")
	}
	data, err := readText(p.root, name, p.maxBytes)
	if err != nil {
		return fileOutput{}, err
	}
	count := strings.Count(string(data), oldText)
	if count == 0 || (count > 1 && !replaceAll) {
		return fileOutput{}, fmt.Errorf("old_text 匹配 %d 次；必须唯一匹配或设置 replace_all", count)
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
	err = fs.WalkDir(p.root.FS(), filepath.ToSlash(name), func(path string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		visited++
		if visited > 20000 || bytesRead >= 32<<20 {
			out.Truncated = true
			return fs.SkipAll
		}
		if walkErr != nil {
			out.Skipped++
			if path == filepath.ToSlash(name) {
				return walkErr
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			out.Skipped++
			return nil
		}
		data, err := readText(p.root, filepath.FromSlash(path), p.maxBytes)
		if err != nil {
			out.Skipped++
			return nil
		}
		bytesRead += int64(len(data))
		for i, line := range strings.Split(string(data), "\n") {
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
				out.Matches = append(out.Matches, match{path, i + 1, line})
			}
		}
		return nil
	})
	return out, err
}
