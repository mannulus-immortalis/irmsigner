//go:build linux

package api

import (
	"time"

	"github.com/rubiojr/go-usbmon"
)

func (a *api) listenUSBEvents() {
	usbEvents, err := usbmon.Listen(a.ctx)
	if err != nil {
		a.log.Err(err).Msg("USB events listen failed")
		return
	}
	go func() {
		for e := range usbEvents {
			act := e.Action()
			if act == "bind" || act == "remove" {
				time.Sleep(100 * time.Millisecond)
				_, _ = a.updateCertList()
			}
		}
	}()
}
