obj-m := filter-functions-ftrace.o filter-functions-livepatch.o \
         ptrace-fix-ftrace.o ptrace-fix-livepatch.o \
         tcp-connect-logger.o udp-send-logger.o \
		 loadavg-lxd-livepatch.o nft-catchall-fix-livepatch.o \
		 cve-2026-98432-livepatch-6.8.o cve-2026-98432-livepatch-6.12.o
		 badepoll-livepatch.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Note: when insmod'd, ".ko" files with '-' in their names register
# under module names where '-' is replaced by '_'.
FT_MOD          := block_functions
LP_MOD          := livepatch_filter
PTRACE_FT_MOD   := ptrace_fix_ftrace
PTRACE_LP_MOD   := ptrace_fix_livepatch
TCL_MOD         := tcp_connect_logger
USL_MOD         := udp_send_logger
LP_LXD          := loadavg_lxd_livepatch
NFT_LP_MOD      := nft_catchall_fix_livepatch
BADEPOLL_LP_MOD	:= badepoll_livepatch
CVE_98432_6_8_MOD   := cve_2026_98432_livepatch_6_8
CVE_98432_6_12_MOD  := cve_2026_98432_livepatch_6_1

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# --- Generic blockers (configurable list) ----------------------------
load-ftrace: all
	sudo insmod filter-functions-ftrace.ko

unload-ftrace:
	sudo rmmod $(FT_MOD)

load-livepatch: all
	sudo insmod filter-functions-livepatch.ko

unload-livepatch:
	echo 0 | sudo tee /sys/kernel/livepatch/$(LP_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(LP_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(LP_MOD)

# --- ptrace exit_mm() dumpability mitigation (commit 31e62c2ebbfd) ----
load-ptrace-ftrace: all
	sudo insmod ptrace-fix-ftrace.ko

unload-ptrace-ftrace:
	sudo rmmod $(PTRACE_FT_MOD)

load-ptrace-livepatch: all
	sudo insmod ptrace-fix-livepatch.ko

unload-ptrace-livepatch:
	echo 0 | sudo tee /sys/kernel/livepatch/$(PTRACE_LP_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(PTRACE_LP_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(PTRACE_LP_MOD)

# --- tcp_v4_connect logger (LIVEPATCH.md tutorial) -------------------
load-tcp-logger: all
	sudo insmod tcp-connect-logger.ko

unload-tcp-logger:
	echo 0 | sudo tee /sys/kernel/livepatch/$(TCL_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(TCL_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(TCL_MOD)

# --- udp_sendmsg logger (sister to tcp-connect-logger) ---------------
load-udp-logger: all
	sudo insmod udp-send-logger.ko

unload-udp-logger:
	echo 0 | sudo tee /sys/kernel/livepatch/$(USL_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(USL_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(USL_MOD)


# --- sysinfo loadavg patch -------------------------------------------
load-loadavg-lxd-livepatch: all
	sudo insmod loadavg-lxd-livepatch.ko

unload-loadavg-lxd-livepatch:
	echo 0 | sudo tee /sys/kernel/livepatch/$(LP_LXD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(LP_LXD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(LP_LXD)

# --- CVE-2026-98432 ipv4 inet_opt/ireq_opt UAF fix -------------------
# Upstream: commit e3f33b0a1d89 (kfree -> kfree_rcu in inet_sock_destruct
# and tcp_v4_reqsk_destructor). Pick the variant matching your kernel.
load-cve-98432-6.8: all
	sudo insmod cve-2026-98432-livepatch-6.8.ko

unload-cve-98432-6.8:
	echo 0 | sudo tee /sys/kernel/livepatch/$(CVE_98432_6_8_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(CVE_98432_6_8_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(CVE_98432_6_8_MOD)

load-cve-98432-6.12: all
	sudo insmod cve-2026-98432-livepatch-6.12.ko

unload-cve-98432-6.12:
	echo 0 | sudo tee /sys/kernel/livepatch/$(CVE_98432_6_12_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(CVE_98432_6_12_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(CVE_98432_6_12_MOD)

# --- CVE-2026-23111 nft_map_catchall_activate UAF fix ----------------
load-nft-fix: all
	sudo insmod nft-catchall-fix-livepatch.ko

unload-nft-fix:
	echo 0 | sudo tee /sys/kernel/livepatch/$(NFT_LP_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(NFT_LP_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done

# --- CVE-2026-46242 ep_remove fix ----------------
load-badepoll-fix: all
	sudo insmod badepoll-livepatch.ko

unload-badepoll-fix:
	echo 0 | sudo tee /sys/kernel/livepatch/$(BADEPOLL_LP_MOD)/enabled
	@echo "Waiting for livepatch transition to complete..."
	@while [ "$$(cat /sys/kernel/livepatch/$(BADEPOLL_LP_MOD)/transition 2>/dev/null)" = "1" ]; do sleep 1; done
	sudo rmmod $(BADEPOLL_LP_MOD)


.PHONY: all clean \
        load-ftrace unload-ftrace \
        load-livepatch unload-livepatch \
        load-ptrace-ftrace unload-ptrace-ftrace \
        load-ptrace-livepatch unload-ptrace-livepatch \
        load-tcp-logger unload-tcp-logger \
        load-udp-logger unload-udp-logger
