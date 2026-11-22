package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func testProject(t *testing.T) (*project, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return &project{root: r, maxBytes: defaultMaxBytes}, dir
}

func TestDirectoryBoundary(t *testing.T) {
	p, dir := testProject(t)
	if _, err := p.write("inside", "inside", ""); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../secret.txt", secret, "escape/secret.txt", "escape/new.txt", "a/../../secret.txt"} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.read(name); err == nil {
				t.Fatal("越界读取应失败")
			}
			if _, err := p.write(name, "changed", ""); err == nil {
				t.Fatal("越界写入应失败")
			}
			if _, err := p.edit(name, "outside", "changed", hash([]byte("outside")), false); err == nil {
				t.Fatal("越界编辑应失败")
			}
			if err := p.mkdir(name); err == nil {
				t.Fatal("越界创建目录应失败")
			}
			if err := p.deleteFile(name, hash([]byte("outside"))); err == nil {
				t.Fatal("越界删除应失败")
			}
			if _, err := p.moveFile(name, "moved", hash([]byte("outside"))); err == nil {
				t.Fatal("越界源路径应失败")
			}
			if _, err := p.moveFile("inside", name, hash([]byte("inside"))); err == nil {
				t.Fatal("越界目标路径应失败")
			}
		})
	}
	if _, err := p.list("escape", 10); err == nil {
		t.Fatal("越界列目录应失败")
	}
	if _, err := p.search(context.Background(), "escape", "outside", 10); err == nil {
		t.Fatal("不能从越界符号链接开始搜索")
	}
	if out, err := p.search(context.Background(), ".", "outside", 10); err != nil || len(out.Matches) != 0 {
		t.Fatalf("搜索不能返回目录外内容：%+v %v", out, err)
	}
	data, err := os.ReadFile(secret)
	if err != nil || string(data) != "outside" {
		t.Fatalf("项目外文件被修改：%q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("项目外创建了文件")
	}
}

func TestWriteVersionAndUTF8(t *testing.T) {
	p, _ := testProject(t)
	if err := p.mkdir("src/中文"); err != nil {
		t.Fatal(err)
	}
	first, err := p.write("src/中文/test.txt", "你好\r\n你好\r\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.write(first.Path, "覆盖", ""); err == nil {
		t.Fatal("禁止盲目覆盖")
	}
	if _, err := p.edit(first.Path, "你好", "再见", first.SHA256, false); err == nil {
		t.Fatal("非唯一替换应失败")
	}
	updated, err := p.edit(first.Path, "你好", "再见", first.SHA256, true)
	if err != nil || updated.Content != "再见\r\n再见\r\n" {
		t.Fatalf("编辑或 CRLF 保留失败：%+v %v", updated, err)
	}
	if _, err := p.write(first.Path, "旧版本", first.SHA256); err == nil {
		t.Fatal("旧版本应被拒绝")
	}
	if _, err := p.write("invalid", string([]byte{0xff}), ""); err == nil {
		t.Fatal("应拒绝无效 UTF-8")
	}
	p.maxBytes = 4
	if _, err := p.read(first.Path); err == nil {
		t.Fatal("应拒绝超大文件")
	}
	if _, err := p.write("large", "12345", ""); err == nil {
		t.Fatal("应拒绝超大写入")
	}
}

func TestConcurrentUpdates(t *testing.T) {
	p, _ := testProject(t)
	first, err := p.write("file", "initial", "")
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			if _, err := p.write("file", "changed", first.SHA256); err == nil {
				success.Add(1)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("应只有一次更新成功，实际 %d", success.Load())
	}
}

func TestLinksAndSpecialFiles(t *testing.T) {
	p, dir := testProject(t)
	outside := filepath.Join(t.TempDir(), "hardlink.txt")
	if err := os.WriteFile(outside, []byte("original"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.write("hardlink", "new", hash([]byte("original"))); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "original" {
		t.Fatal("不能通过硬链接修改目录外文件")
	}
	info, err := p.root.Stat("hardlink")
	if err != nil || info.Mode().Perm() != 0750 {
		t.Fatal("应保留文件权限")
	}
	if err := os.Symlink("hardlink", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.read("link"); err != nil {
		t.Fatal("应允许目录内的相对符号链接读取", err)
	}
	if _, err := p.write("link", "bad", hash([]byte("new"))); err == nil {
		t.Fatal("禁止通过符号链接写入")
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.read("fifo"); err == nil {
		t.Fatal("应拒绝 FIFO")
	}
	if _, err := p.list("fifo", 10); err == nil {
		t.Fatal("不能列出 FIFO")
	}
}

func TestSearchAndReadOnly(t *testing.T) {
	p, _ := testProject(t)
	if _, err := p.write("file.txt", strings.Repeat("needle\n", 3), ""); err != nil {
		t.Fatal(err)
	}
	out, err := p.search(context.Background(), ".", "needle", 1)
	if err != nil || !out.Truncated || len(out.Matches) != 1 || out.Matches[0].Line != 1 {
		t.Fatalf("搜索结果错误：%+v %v", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.search(ctx, ".", "needle", 10); err == nil {
		t.Fatal("搜索应响应取消")
	}
	p.readOnly = true
	if _, err := p.write("file.txt", "x", hash([]byte(strings.Repeat("needle\n", 3)))); err == nil {
		t.Fatal("只读模式应拒绝写入")
	}
	if err := p.mkdir("nope"); err == nil {
		t.Fatal("只读模式应拒绝创建目录")
	}
}
