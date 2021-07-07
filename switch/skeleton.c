// SPDX-License-Identifier: GPL-2.0
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpfnic_shared.h"

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

struct bpf_map_def SEC("maps") forwarding_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__be64),
	.value_size = sizeof(int),
	.max_entries = 10000,
};


SEC("socket")
int always_accept(struct __sk_buff *skb)
{
	return 1;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
