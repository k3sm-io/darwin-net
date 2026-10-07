/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package linkwatch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The darwin struct ifmediareq (net/if.h, under #pragma pack(4)):
// ifm_name[IFNAMSIZ], then the ints ifm_current, ifm_mask, ifm_status,
// ifm_active, ifm_count, then the pointer ifm_ulist at offset 36, 44 bytes in
// all, which is the size SIOCGIFMEDIA encodes. golang.org/x/sys/unix has no
// darwin binding for it, so the request is laid out by hand.
const (
	ifmediareqLen   = 44
	ifmStatusOffset = unix.IFNAMSIZ + 8
	ifmAValid       = 0x1 // IFM_AVALID: the IFM_ACTIVE bit is valid
	ifmActive       = 0x2 // IFM_ACTIVE: the interface has a working carrier
)

// MediaCarrier reads iface's carrier with SIOCGIFMEDIA on an AF_INET datagram
// socket, which needs no privilege. It reports known false, with no error, when
// the driver keeps no media status (IFM_AVALID clear) or does not implement the
// request at all (lo0, utun), so such an interface is never marked down for the
// lack of a carrier report.
func MediaCarrier(iface string) (up, known bool, err error) {
	if len(iface) >= unix.IFNAMSIZ {
		return false, false, fmt.Errorf("interface name %q too long", iface)
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return false, false, fmt.Errorf("open media socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }() // nothing was written through it

	var req [ifmediareqLen]byte
	copy(req[:unix.IFNAMSIZ], iface)
	// golang.org/x/sys/unix exports no darwin ioctl taking an arbitrary
	// pointer (its libSystem ioctlPtr is unexported), so the request goes
	// through syscall(2); ioctl's number is part of the stable BSD ABI.
	//lint:ignore SA1019 no exported libSystem ioctl wrapper accepts an ifmediareq
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCGIFMEDIA), uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		if errors.Is(errno, unix.EINVAL) || errors.Is(errno, unix.EOPNOTSUPP) || errors.Is(errno, unix.ENOTTY) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("SIOCGIFMEDIA %s: %w", iface, errno)
	}
	status := binary.NativeEndian.Uint32(req[ifmStatusOffset:])
	if status&ifmAValid == 0 {
		return false, false, nil
	}
	return status&ifmActive != 0, true, nil
}
