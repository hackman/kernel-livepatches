obj-m := filter-functions-ftrace.o filter-functions-livepatch.o \
         ptrace-fix-ftrace.o ptrace-fix-livepatch.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Note: when insmod'd, ".ko" files with '-' in their names register
# under module names where '-' is replaced by '_'.
FT_MOD          := block_functions
LP_MOD          := livepatch_filter
PTRACE_FT_MOD   := ptrace_fix_ftrace
PTRACE_LP_MOD   := ptrace_fix_livepatch

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

.PHONY: all clean \
        load-ftrace unload-ftrace \
        load-livepatch unload-livepatch \
        load-ptrace-ftrace unload-ptrace-ftrace \
        load-ptrace-livepatch unload-ptrace-livepatch
