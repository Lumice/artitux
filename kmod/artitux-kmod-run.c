/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "artitux_kmod.h"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s --status\n"
		"  %s [--umip] [--xcr0] [--] <command> [args...]\n",
		prog, prog);
}

int main(int argc, char **argv)
{
	uint32_t flags = 0;
	int status_only = 0;
	int i = 1;

	while (i < argc) {
		if (strcmp(argv[i], "--status") == 0) {
			status_only = 1;
			i++;
		} else if (strcmp(argv[i], "--umip") == 0) {
			flags |= ARTITUX_FLAG_UMIP;
			i++;
		} else if (strcmp(argv[i], "--xcr0") == 0) {
			flags |= ARTITUX_FLAG_XCR0_7;
			i++;
		} else if (strcmp(argv[i], "--") == 0) {
			i++;
			break;
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			break;
		}
	}

	int fd = open(ARTITUX_KMOD_DEVICE_PATH, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "artitux-kmod-run: cannot open %s: %s\n",
			ARTITUX_KMOD_DEVICE_PATH, strerror(errno));
		return 1;
	}

	if (status_only) {
		struct artitux_kmod_info info;
		memset(&info, 0, sizeof(info));
		if (ioctl(fd, ARTITUX_IOCTL_GET_INFO, &info) != 0) {
			perror("ARTITUX_IOCTL_GET_INFO");
			close(fd);
			return 1;
		}
		printf("abi=%u host_xcr0=0x%llx caps=0x%x (umip=%d xcr0_hook=%d xcr0_native=%d) tracked=%u active_xcr0=%u\n",
		       info.abi_version,
		       (unsigned long long)info.host_xcr0,
		       info.capabilities,
		       !!(info.capabilities & ARTITUX_CAP_UMIP_HOOK),
		       !!(info.capabilities & ARTITUX_CAP_XCR0_HOOK),
		       !!(info.capabilities & ARTITUX_CAP_XCR0_NATIVE),
		       info.tracked_tasks,
		       info.active_xcr0_tasks);
		close(fd);
		return 0;
	}

	if (i >= argc) {
		usage(argv[0]);
		close(fd);
		return 2;
	}

	if (flags && ioctl(fd, ARTITUX_IOCTL_ARM_EXEC, &flags) != 0) {
		fprintf(stderr, "artitux-kmod-run: ARM_EXEC(0x%x) failed: %s\n",
			flags, strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);

	execvp(argv[i], &argv[i]);
	fprintf(stderr, "artitux-kmod-run: exec %s failed: %s\n", argv[i], strerror(errno));
	return 127;
}
