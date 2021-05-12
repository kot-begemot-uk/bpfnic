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
#include "bpf_insn.h"

static int permit_fd, deny_fd;
static char log_buf[1 << 16];

static void permit_load(char *pathname)
{

    struct bpf_insn prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
    };
    permit_fd = bpf_load_program(BPF_PROG_TYPE_SOCKET_FILTER, prog,
                    ARRAY_SIZE(prog), "GPL", 0,
                    log_buf, sizeof(log_buf));
    if (permit_fd < 0)
        error(1, errno, "failed to load prog\n%s\n", log_buf);

    if (bpf_obj_pin(permit_fd, pathname))
        error(1, errno, "bpf_obj_pin");
}

static void deny_load(char *pathname)
{
    struct bpf_insn prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    deny_fd = bpf_load_program(BPF_PROG_TYPE_SOCKET_FILTER, prog,
                    ARRAY_SIZE(prog), "GPL", 0,
                    log_buf, sizeof(log_buf));
    if (deny_fd < 0)
        error(1, errno, "failed to load prog\n%s\n", log_buf);

    if (bpf_obj_pin(deny_fd, pathname))
        error(1, errno, "bpf_obj_pin");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        error(1, EINVAL, "insufficient arguments");
    }
    permit_load(argv[1]);
    deny_load(argv[2]);
    close(permit_fd);
    close(deny_fd);
    return 0;
}
