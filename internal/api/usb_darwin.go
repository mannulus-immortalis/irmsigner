//go:build darwin

package api

import (
	"crypto/md5"
	"os/exec"
	"time"
)

func (a *api) listenUSBEvents() {
	go func() {
		prev := usbSnapshot()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				curr := usbSnapshot()
				if curr != prev {
					prev = curr
					time.Sleep(100 * time.Millisecond)
					_, _ = a.updateCertList()
				}
			}
		}
	}()
}

func usbSnapshot() [16]byte {
	out, _ := exec.Command("ioreg", "-r", "-c", "IOUSBDevice").Output()
	return md5.Sum(out)
}
