//go:build linux
// +build linux

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type Report struct {
	AlgSockets []Socket `json:"alg_sockets"`
	Error      error    `json:"error,omitempty"`
}

type Socket struct {
	Pid   int    `json:"pid"`
	Fd    int    `json:"fd"`
	Comm  string `json:"comm"`
	Error string `json:"error,omitempty,omitzero"`
}

var (
	Stream                  bool
	IgnorePermissionsErrors bool
)

func main() {

	flag.BoolVar(&Stream, "stream", false, "enable streaming mode")
	flag.BoolVar(&IgnorePermissionsErrors, "ignore-permissions-errors", false, "ignore permission errors")
	flag.Parse()

	report, err := scanProc()
	if err != nil {
		report.Error = fmt.Errorf("scan failed: %w", err)
	}

	if !Stream {
		data, _ := json.MarshalIndent(report, "", "    ")
		fmt.Println(string(data))
	}

}

func scanProc() (report Report, err error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return Report{}, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil && !ignorable(err) {
			fmt.Fprintf(os.Stderr, "read comm for pid %d: %v\n", pid, err)
		}

		comm := strings.TrimSpace(string(b))

		report.AlgSockets = append(report.AlgSockets, scanProcess(pid, comm)...)

	}

	return report, nil
}

func scanProcess(pid int, comm string) (result []Socket) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		if !ignorable(err) {
			newSocket := Socket{
				Pid:   pid,
				Fd:    -1,
				Comm:  comm,
				Error: fmt.Sprintf("unable to read pid %d file descriptors, potentially try root: %v", pid, err),
			}

			result = append(result, newSocket)
		}
		return
	}

	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		newSocket := Socket{
			Pid:  pid,
			Fd:   fd,
			Comm: comm,
		}

		isALG, err := isAlgSocket(pid, fd)
		if err != nil {
			if !ignorable(err) {
				newSocket.Error = err.Error()
				if Stream {
					json.NewEncoder(os.Stdout).Encode(newSocket)
				}
			}

			continue
		}

		if !isALG {
			continue
		}

		if Stream {
			json.NewEncoder(os.Stdout).Encode(newSocket)
		}

		result = append(result, newSocket)

	}

	return result
}

func isAlgSocket(pid, fd int) (bool, error) {
	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	fi, err := os.Stat(procPath)
	if err != nil {
		return false, err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return false, nil
	}

	buf := make([]byte, 32)
	n, err := syscall.Getxattr(procPath, "system.sockprotoname", buf)
	if err != nil {
		if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.EOPNOTSUPP) {
			return false, nil
		}
		return false, err
	}
	proto := strings.TrimRight(string(buf[:n]), "\x00")
	return proto == "ALG", nil
}

func ignorable(err error) bool {
	return errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.EBADF) ||
		errors.Is(err, syscall.ENOTSOCK) ||
		(errors.Is(err, fs.ErrPermission) && IgnorePermissionsErrors) ||
		strings.Contains(err.Error(), "not a socket")
}
