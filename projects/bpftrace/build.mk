# Copyright (c) Meta Platforms, Inc. and affiliates.

BPFTRACE_ANDROID_DEPS = bcc cereal elfutils flex llvm stdc++fs
BPFTRACE_HOST_DEPS = cmake flex
$(eval $(call project-define,bpftrace))

BPFTRACE_EXTRA_LDFLAGS = "-L$(abspath $(ANDROID_OUT_DIR))/lib"

$(BPFTRACE_ANDROID): $(ANDROID_OUT_DIR)/lib/libc++_shared.so
ifeq ($(BUILD_TYPE), Debug)
	cd $(BPFTRACE_ANDROID_BUILD_DIR) && $(MAKE) install -j $(THREADS)
else
	cd $(BPFTRACE_ANDROID_BUILD_DIR) && $(MAKE) install/strip -j $(THREADS)
endif
	touch $@

$(BPFTRACE_ANDROID_BUILD_DIR): $(HOST_OUT_DIR)/bin/flex
	-mkdir $@
	cd $@ && LDFLAGS="$(BPFTRACE_EXTRA_LDFLAGS)" $(CMAKE) $(BPFTRACE_SRCS) \
		$(ANDROID_EXTRA_CMAKE_FLAGS) \
		-DBUILD_TESTING=OFF \
		-DENABLE_MAN=OFF \
		-DFLEX_EXECUTABLE=$(abspath $(HOST_OUT_DIR)/bin/flex) \
		-DALLOW_UNSAFE_PROBE=ON

$(ANDROID_OUT_DIR)/share/bpftrace/tools:
	mkdir -p $@
	cp $(BPFTRACE_SOURCES)/tools/*.bt $@

BPFTRACE_COMMIT = v0.14.1
BPFTRACE_REPO = https://github.com/iovisor/bpftrace.git/
projects/bpftrace/sources:
	git clone $(BPFTRACE_REPO) $@
	cd $@ && git checkout $(BPFTRACE_COMMIT)
