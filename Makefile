# Local build & verification for xdp-rate-limit-smart.
# This mirrors what install.sh compiles, but writes into ./build so you can
# test compilation and the verifier on any Linux box before touching a server.
#
#   make            # compile BPF object + loader into ./build
#   make bpf        # BPF object only
#   make loader     # userspace loader only
#   make verify     # dump the compiled program (needs bpftool)
#   make pycheck    # byte-compile the Python daemon
#   make clean

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  TARGET_ARCH := x86
else ifeq ($(ARCH),amd64)
  TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
  TARGET_ARCH := arm64
else ifeq ($(ARCH),arm64)
  TARGET_ARCH := arm64
else ifeq ($(ARCH),armv7l)
  TARGET_ARCH := arm
else ifeq ($(ARCH),ppc64le)
  TARGET_ARCH := powerpc
else ifeq ($(ARCH),s390x)
  TARGET_ARCH := s390
else
  TARGET_ARCH := x86
endif

MULTIARCH := $(shell gcc -print-multiarch 2>/dev/null)
ifneq ($(MULTIARCH),)
  BPF_INCLUDES := -I/usr/include/$(MULTIARCH)
endif

CLANG   ?= clang
CC      ?= gcc
BUILD   := build
BPF_OBJ := $(BUILD)/xdp_rate_limit.bpf.o
LOADER  := $(BUILD)/xdp-rate-loader

.PHONY: all bpf loader verify pycheck clean

all: bpf loader

bpf: $(BPF_OBJ)

loader: $(LOADER)

$(BPF_OBJ): src/xdp_rate_limit.bpf.c | $(BUILD)
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) $(BPF_INCLUDES) \
		-c $< -o $@

$(LOADER): src/xdp_loader.c | $(BUILD)
	$(CC) -O2 -g -Wall $< -o $@ -lbpf -lelf -lz

$(BUILD):
	mkdir -p $(BUILD)

# Static check of the compiled object: dumps maps + program without loading.
verify: $(BPF_OBJ)
	bpftool prog dump xlated pinned /dev/null 2>/dev/null || true
	bpftool --version
	llvm-objdump -S $(BPF_OBJ) | head -n 40

pycheck:
	python3 -m py_compile src/xdp_rate_daemon.py
	@echo "python daemon compiles OK"

clean:
	rm -rf $(BUILD)
