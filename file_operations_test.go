package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestMoveAndDeleteFile(t *testing.T) {
	p, _ := testProject(t)
	if err := p.mkdir("目标"); err != nil {
		t.Fatal(err)
	}
	first, err := p.write("原文.txt", "你好\r\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.root.Chmod(first.Path, 0750); err != nil {
		t.Fatal(err)
	}
	moved, err := p.moveFile(first.Path, "目标/新文.txt", first.SHA256)
	if err != nil || moved.Source != first.Path || moved.Destination != "目标/新文.txt" || moved.SHA256 != first.SHA256 {
		t.Fatalf("移动结果错误：%+v %v", moved, err)
	}
	if _, err := p.root.Stat(first.Path); !os.IsNotExist(err) {
		t.Fatal("移动后原文件应不存在")
	}
	read, err := p.read(moved.Destination)
	if err != nil || read.Content != first.Content || read.SHA256 != first.SHA256 {
		t.Fatal("移动必须保留原内容和版本", err)
	}
	if info, err := p.root.Stat(moved.Destination); err != nil || info.Mode().Perm() != 0750 {
		t.Fatal("移动必须保留权限", err)
	}
	if err := p.deleteFile(moved.Destination, moved.SHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := p.root.Stat(moved.Destination); !os.IsNotExist(err) {
		t.Fatal("删除后文件应不存在")
	}
}

func TestMutationVersionAndReadOnly(t *testing.T) {
	p, _ := testProject(t)
	first, err := p.write("source", "original", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"", hash([]byte("stale"))} {
		if err := p.deleteFile(first.Path, expected); err == nil {
			t.Fatal("删除应拒绝缺少或过期版本")
		}
		if _, err := p.moveFile(first.Path, "destination", expected); err == nil {
			t.Fatal("移动应拒绝缺少或过期版本")
		}
	}
	p.readOnly = true
	if err := p.deleteFile(first.Path, first.SHA256); err == nil {
		t.Fatal("只读模式应拒绝删除")
	}
	if _, err := p.moveFile(first.Path, "destination", first.SHA256); err == nil {
		t.Fatal("只读模式应拒绝移动")
	}
	if read, err := p.read(first.Path); err != nil || read.Content != first.Content {
		t.Fatal("失败操作应保留原文件", err)
	}
}

func TestMutationProtectsGitAndLinks(t *testing.T) {
	p, dir := testProject(t)
	for _, parent := range []string{".git", "nested/.git", "ordinary"} {
		if err := p.mkdir(parent); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"source", ".git/config", "nested/.git/config", "ordinary/file"} {
		if _, err := p.write(name, "original", ""); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"git-alias": ".git", "ordinary-alias": "ordinary", "file-alias": "source"} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	version := hash([]byte("original"))
	for _, name := range []string{"", ".", ".git", "./.git/", ".git/config", "git-alias/config", "ordinary-alias/file", "file-alias"} {
		t.Run(name, func(t *testing.T) {
			if err := p.deleteFile(name, version); err == nil {
				t.Fatal("禁止删除受保护路径或符号链接")
			}
			if _, err := p.moveFile(name, "moved", version); err == nil {
				t.Fatal("禁止移动受保护路径或符号链接")
			}
			if _, err := p.moveFile("source", name, version); err == nil {
				t.Fatal("禁止向受保护路径或符号链接移动")
			}
		})
	}
	// 子目录中的 .git 文件和内部普通文件均不受根目录保护规则影响。
	if _, err := p.write("ordinary/.git", "gitdir: ../metadata", ""); err != nil {
		t.Fatal(err)
	}
	worktreeVersion := hash([]byte("gitdir: ../metadata"))
	if _, err := p.moveFile("ordinary/.git", "nested/.git/worktree", worktreeVersion); err != nil {
		t.Fatal("应允许移动子目录中的 .git 文件", err)
	}
	if err := p.deleteFile("nested/.git/worktree", worktreeVersion); err != nil {
		t.Fatal("应允许删除子目录 .git 内的文件", err)
	}
	if _, err := p.moveFile("nested/.git/config", "ordinary/.git", version); err != nil {
		t.Fatal("应允许从子目录 .git 内移动到子目录 .git 文件", err)
	}
	if err := p.deleteFile("ordinary/.git", version); err != nil {
		t.Fatal("应允许删除子目录中的 .git 文件", err)
	}
	for _, name := range []string{"source", ".git/config", "ordinary/file"} {
		if read, err := p.read(name); err != nil || read.Content != "original" {
			t.Fatal("受保护的文件应保持不变", err)
		}
	}
}

func TestMutationProtectsRootGitFile(t *testing.T) {
	p, _ := testProject(t)
	first, err := p.write(".git", "gitdir: ../metadata", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.deleteFile("./.git", first.SHA256); err == nil {
		t.Fatal("禁止删除根目录 worktree 的 .git 文件")
	}
	if _, err := p.moveFile(".git", "moved", first.SHA256); err == nil {
		t.Fatal("禁止移动根目录 worktree 的 .git 文件")
	}
	if read, err := p.read(".git"); err != nil || read.Content != first.Content {
		t.Fatal("根目录 .git 文件应保持不变", err)
	}
}

func TestMoveNeverOverwrites(t *testing.T) {
	p, dir := testProject(t)
	first, err := p.write("source", "source", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.write("existing", "keep", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.mkdir("directory"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"source", "existing", "directory", "dangling", "missing/child"} {
		if _, err := p.moveFile(first.Path, destination, first.SHA256); err == nil {
			t.Fatalf("应拒绝目标 %s", destination)
		}
	}
	if read, err := p.read("existing"); err != nil || read.Content != "keep" {
		t.Fatal("目标文件不能被覆盖", err)
	}
	if read, err := p.read(first.Path); err != nil || read.Content != first.Content {
		t.Fatal("失败移动不能丢失源文件", err)
	}
}

func TestMutationRejectsNonTextAndDirectories(t *testing.T) {
	p, dir := testProject(t)
	if err := p.mkdir("directory"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "binary"), []byte{0xff, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.write("large", "12345", ""); err != nil {
		t.Fatal(err)
	}
	p.maxBytes = 4
	for _, name := range []string{"directory", "binary", "fifo", "large", "missing"} {
		if err := p.deleteFile(name, hash([]byte("12345"))); err == nil {
			t.Fatalf("不应删除 %s", name)
		}
		if _, err := p.moveFile(name, "moved", hash([]byte("12345"))); err == nil {
			t.Fatalf("不应移动 %s", name)
		}
	}
}

func TestConcurrentMoveAndDelete(t *testing.T) {
	p, _ := testProject(t)
	first, err := p.write("source", "original", "")
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			if err := p.deleteFile(first.Path, first.SHA256); err == nil {
				success.Add(1)
			}
		})
		wg.Go(func() {
			if _, err := p.moveFile(first.Path, "moved", first.SHA256); err == nil {
				success.Add(1)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("并发删除和移动只能成功一次，实际 %d", success.Load())
	}
}
