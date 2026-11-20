/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARTITUX_KMOD_UAPI_H
#define ARTITUX_KMOD_UAPI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <linux/ioctl.h>
#include <linux/types.h>
#endif

#define ARTITUX_KMOD_DEVICE_PATH "/dev/artitux"
#define ARTITUX_KMOD_ABI_VERSION 1U

/* Per-process policy flags (inherited across fork, clone, and exec). */
#define ARTITUX_FLAG_UMIP    (1U << 0) /* Non-zero SGDT/SIDT limit under UMIP */
#define ARTITUX_FLAG_XCR0_7  (1U << 1) /* Lazy per-process userspace XCR0 = 7 */
#define ARTITUX_FLAG_ALL     (ARTITUX_FLAG_UMIP | ARTITUX_FLAG_XCR0_7)

/* Host capability bits reported by ARTITUX_IOCTL_GET_INFO. */
#define ARTITUX_CAP_UMIP_HOOK   (1U << 0) /* Host has UMIP and fixup hook is active */
#define ARTITUX_CAP_XCR0_HOOK   (1U << 1) /* Host XCR0 > 7 and lazy XCR0 hook is active */
#define ARTITUX_CAP_XCR0_NATIVE (1U << 2) /* Host XCR0 is already 7 natively */

struct artitux_kmod_info {
	__u32 abi_version;
	__u32 capabilities;
	__u64 host_xcr0;
	__u32 active_flags;
	__u32 pending_flags;
	__u32 tracked_tasks;
	__u32 active_xcr0_tasks;
};

struct artitux_task_state {
	__u32 active_flags;
	__u32 pending_flags;
};

#define ARTITUX_IOCTL_MAGIC    'A'
#define ARTITUX_IOCTL_GET_INFO  _IOR(ARTITUX_IOCTL_MAGIC, 0, struct artitux_kmod_info)
#define ARTITUX_IOCTL_ARM_EXEC  _IOW(ARTITUX_IOCTL_MAGIC, 1, __u32)
#define ARTITUX_IOCTL_GET_STATE _IOR(ARTITUX_IOCTL_MAGIC, 2, struct artitux_task_state)

#endif /* ARTITUX_KMOD_UAPI_H */
