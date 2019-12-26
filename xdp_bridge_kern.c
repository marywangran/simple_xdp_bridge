// xdp_bridge_kern.c
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include "bpf_helpers.h"

// mac_port_map保存该交换机的MAC/端口映射
struct bpf_map_def SEC("maps") mac_port_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(long),
	.value_size = sizeof(int),
	.max_entries = 100,
};

// 以下函数是网桥转发路径的eBPF主函数实现
SEC("xdp_br")
int xdp_bridge_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	long dst_mac = 0;
	int in_index = ctx->ingress_ifindex, *out_index;
	// data即数据包开始位置
	struct ethhdr *eth = (struct ethhdr *)data;
	char info_fmt[] = "Destination Address: %lx   Redirect to:[%d]   From:[%d]\n";

	// 畸形包必须丢弃，否则无法通过内核的eBPF字节码合法性检查
	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_DROP;
	}

	// 获取目标MAC地址
	__builtin_memcpy(&dst_mac, eth->h_dest, 6);

	// 在MAC/端口映射表里查找对应该MAC的端口
	out_index = bpf_map_lookup_elem(&mac_port_map, &dst_mac);
	if (out_index == NULL) { 
		// 如若找不到，则上传到慢速路径，必要时由控制路径更新MAC/端口表项。
		return XDP_PASS;
	}

	// 非Hairpin下生效
	if (in_index == *out_index) { // Hairpin ?
		return XDP_DROP;
	}

	// 简单打印些调试信息
	bpf_trace_printk(info_fmt, sizeof(info_fmt), dst_mac, *out_index, in_index);

	// 转发到出端口
	return  bpf_redirect(*out_index, 0);
}

char _license[] SEC("license") = "GPL";

