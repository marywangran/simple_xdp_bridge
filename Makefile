# ... samples/bpf/Makefile
always += xdp_bridge_kern.o
hostprogs-y += xdp_bridge
xdp_bridge-objs := xdp_bridge_user.o
