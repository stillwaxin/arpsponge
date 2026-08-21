//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type pidFile struct {
	path string
	lock *os.File
	file *os.File
}

func acquirePIDFile(path string) (*pidFile, error) {
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open pidfile lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock pidfile: %w", err)
	}

	p := &pidFile{path: path, lock: lock}
	if err := p.write(); err != nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		return nil, err
	}
	return p, nil
}

func (p *pidFile) write() error {
	dir := filepath.Dir(p.path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(p.path)+".")
	if err != nil {
		return fmt.Errorf("create pidfile: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set pidfile permissions: %w", err)
	}
	if _, err := fmt.Fprintf(temp, "%d\n", os.Getpid()); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write pidfile: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync pidfile: %w", err)
	}
	if err := os.Rename(tempName, p.path); err != nil {
		_ = temp.Close()
		return fmt.Errorf("install pidfile: %w", err)
	}
	p.file = temp
	if _, err := p.file.Stat(); err != nil {
		_ = p.file.Close()
		p.file = nil
		return fmt.Errorf("stat pidfile: %w", err)
	}
	return nil
}

func (p *pidFile) Close() error {
	if p == nil || p.lock == nil {
		return nil
	}

	var errs []error
	info, err := p.file.Stat()
	if err != nil {
		errs = append(errs, fmt.Errorf("stat pidfile during cleanup: %w", err))
	}
	if err == nil {
		current, statErr := os.Stat(p.path)
		if statErr == nil {
			if os.SameFile(current, info) {
				if err := os.Remove(p.path); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, fmt.Errorf("remove pidfile: %w", err))
				}
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("stat pidfile during cleanup: %w", statErr))
		}
	}

	if err := p.file.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close pidfile: %w", err))
	}
	p.file = nil
	if err := syscall.Flock(int(p.lock.Fd()), syscall.LOCK_UN); err != nil {
		errs = append(errs, fmt.Errorf("unlock pidfile: %w", err))
	}
	if err := p.lock.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close pidfile lock: %w", err))
	}
	p.lock = nil
	return errors.Join(errs...)
}
