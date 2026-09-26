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

package proxy

import "golang.org/x/sys/unix"

// maxFilesPerProc returns kern.maxfilesperproc, the kernel's per-process fd
// allocation cap, which binds regardless of RLIMIT_NOFILE.
func maxFilesPerProc() (uint64, error) {
	n, err := unix.SysctlUint32("kern.maxfilesperproc")
	if err != nil {
		return 0, err
	}
	return uint64(n), nil
}
