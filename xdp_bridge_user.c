// xdp_bridge_user.c

#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#include "bpf_util.h"

int flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int mac_port_map_fd;
static int *ifindex_list;

// 退出时卸载掉XDP的eBPF字节码
static void int_exit(int sig)
{
	int i = 0;
	for (i = 0; i < 2; i++) {
		bpf_set_link_xdp_fd(ifindex_list[i], -1, 0);
	}
	exit(0);
}

int main(int argc, char *argv[])
{
	int sock, i;
	char buf[1024];
	char filename[64];
	static struct sockaddr_nl g_addr;
	struct bpf_object *obj;
	struct bpf_prog_load_attr prog_load_attr = {
		// prog_type指明eBPF字节码注入的位置，我们网桥的例子中当然是XDP
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	int prog_fd;

	snprintf(filename, sizeof(filename), "xdp_bridge_kern.o");
	prog_load_attr.file = filename;

	// 载入eBPF字节码
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		return 1;
	}

	mac_port_map_fd = bpf_object__find_map_fd_by_name(obj, "mac_port_map");
	ifindex_list = (int *)calloc(2, sizeof(int *));

	// 我们的例子中仅仅支持两个端口的网桥，事实上可以多个。
	ifindex_list[0] = if_nametoindex(argv[1]);
	ifindex_list[1] = if_nametoindex(argv[2]);

	for (i = 0; i < 2/*total */; i++) {
		// 将eBPF字节码注入到感兴趣网卡的XDP
		if (bpf_set_link_xdp_fd(ifindex_list[i], prog_fd, flags) < 0) {
			printf("link set xdp fd failed\n");
			return 1;
		}
	}
	signal(SIGINT, int_exit);

	bzero(&g_addr, sizeof(g_addr));
	g_addr.nl_family = AF_NETLINK;
	g_addr.nl_groups = RTM_NEWNEIGH;

	if ((sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
		int_exit(0);
		return -1;
	}

	if (bind(sock, (struct sockaddr *) &g_addr, sizeof(g_addr)) < 0) {
		int_exit(0);
		return 1;
	}

	// 持续监听socket，捕获Linux网桥上传的notify信息，从而更新，删除eBPF的map里特定的MAC/端口表项
	while (1) {
		int len;
		struct nlmsghdr *nh;
		struct ndmsg *ifimsg ;
		int ifindex = 0;
		unsigned char *cmac;
		unsigned long lkey = 0;

		len = recv(sock, buf, sizeof(buf), 0);
		if (len <= 0) continue;

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
			ifimsg = NLMSG_DATA(nh) ;
			if (ifimsg->ndm_family != AF_BRIDGE) {
				continue;
			}

			// 获取notify信息中的端口
			ifindex = ifimsg->ndm_ifindex;
			for (i = 0; i < 2; i++) {
				if (ifindex == ifindex_list[i]) break;
			}
			if (i == 2) continue;

			// 获取notify信息中的MAC地址
			cmac = (unsigned char *)ifimsg + sizeof(struct ndmsg) + 4;

			memcpy(&lkey, cmac, 6);
			if (nh->nlmsg_type == RTM_DELNEIGH) {
				bpf_map_delete_elem(mac_port_map_fd, (const void *)&lkey);
				printf("Delete XDP bpf map-[HW Address:Port] item Key:[%lx]  Value:[%d]\n", lkey, ifindex);
			} else if (nh->nlmsg_type == RTM_NEWNEIGH) {
				bpf_map_update_elem(mac_port_map_fd, (const void *)&lkey, (const void *)&ifindex, 0);
				printf("Update XDP bpf map-[HW Address:Port]  item Key:[%lx]  Value:[%d]\n", lkey, ifindex);
			}
		}
	}
}

