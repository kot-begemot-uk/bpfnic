// SPDX-License-Identifier: GPL-2.0-only
/*
 *  loader/demo-loader.c
 *
 *  Copyright (C) 2021 Red Hat Inc
 *  Copyright (C) 2021 Cambridge Greys Ltd
 *
 * Author: Anton Ivanov
 *
 */

#define _GNU_SOURCE

#define offsetof(type, member)    __builtin_offsetof(type, member)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int prog_fd;

static void prog_load(char *pathname, char *pinname)
{
    struct bpf_object *obj;
    struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_SOCKET_FILTER,
        .file = pathname,
	};

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		error(1, errno, "failed to load prog");

    if (prog_fd < 0)
        error(1, errno, "failed to load prog\n");

    if (bpf_obj_pin(prog_fd, pinname))
        error(1, errno, "bpf_obj_pin");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        error(1, EINVAL, "insufficient arguments");
    }
    prog_load(argv[1], argv[2]);
    close(prog_fd);
    return 0;
}
