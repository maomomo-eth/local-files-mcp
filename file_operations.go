package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// 删除和移动不允许操作根目录的 Git 元数据，也不接受项目根目录。
func mutationPath(name string) (string, error) {
	name, err := cleanPath(name)
	if err != nil {
		return "", err
	}
	if name == "." {
		return "", errors.New("不能删除或移动项目根目录")
	}
	if name == ".git" || strings.HasPrefix(name, ".git"+string(filepath.Separator)) {
		return "", errors.New("禁止删除或移动项目根目录的 .git 及其内部文件")
	}
	return name, nil
}

// 逐级以 O_NOFOLLOW 打开并固定父目录，防止符号链接绕过根目录 .git 保护。
func (p *project) mutationParent(name string) (*os.File, error) {
	dir, err := p.root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(name)
	if parent != "." {
		for _, part := range strings.Split(parent, string(filepath.Separator)) {
			fd, err := unix.Openat(int(dir.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			dir.Close()
			if err != nil {
				return nil, err
			}
			dir = os.NewFile(uintptr(fd), part)
		}
	}
	return dir, nil
}

func (p *project) mutationVersion(dir *os.File, base, expected string) error {
	// 直接相对固定目录打开末级文件，不让 os.Root 解析符号链接。
	fd, err := unix.Openat(int(dir.Fd()), base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), base)
	defer f.Close()
	data, err := readTextFile(f, p.maxBytes)
	if err != nil {
		return err
	}
	if expected == "" || hash(data) != expected {
		return errors.New("文件版本不匹配：请先 read_file，再提供返回的 expected_sha256")
	}
	return nil
}

func (p *project) deleteFile(name, expected string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readOnly {
		return errors.New("服务处于只读模式")
	}
	name, err := mutationPath(name)
	if err != nil {
		return err
	}
	dir, err := p.mutationParent(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	base := filepath.Base(name)
	if err := p.mutationVersion(dir, base, expected); err != nil {
		return err
	}
	// 不使用 AT_REMOVEDIR，任何情况下都不会递归删除目录。
	return unix.Unlinkat(int(dir.Fd()), base, 0)
}

type moveOutput struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	SHA256      string `json:"sha256"`
}

func (p *project) moveFile(source, destination, expected string) (moveOutput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.readOnly {
		return moveOutput{}, errors.New("服务处于只读模式")
	}
	source, err := mutationPath(source)
	if err != nil {
		return moveOutput{}, err
	}
	destination, err = mutationPath(destination)
	if err != nil {
		return moveOutput{}, err
	}
	srcDir, err := p.mutationParent(source)
	if err != nil {
		return moveOutput{}, err
	}
	defer srcDir.Close()
	dstDir, err := p.mutationParent(destination)
	if err != nil {
		return moveOutput{}, err
	}
	defer dstDir.Close()
	if err := p.mutationVersion(srcDir, filepath.Base(source), expected); err != nil {
		return moveOutput{}, err
	}
	// 原子地拒绝任何已有目标（包括符号链接），避免检查后被抢先创建而覆盖。
	if err := unix.Renameat2(int(srcDir.Fd()), filepath.Base(source), int(dstDir.Fd()), filepath.Base(destination), unix.RENAME_NOREPLACE); err != nil {
		return moveOutput{}, err
	}
	return moveOutput{filepath.ToSlash(source), filepath.ToSlash(destination), expected}, nil
}
