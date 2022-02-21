bpf_sources = bpf/ovn_xdp.c
bpf_headers =
bpf_extra =

dist_sources = $(bpf_sources)
dist_headers = $(bpf_headers)
build_sources = $(dist_sources)
build_headers = $(dist_headers)
build_objects = $(patsubst %.c,%.o,$(build_sources))

LLC ?=  llc
CLANG ?= clang

bpf: $(build_objects)
bpf/ovn_xdp.o: $(bpf_sources) $(bpf_headers)
	$(MKDIR_P) $(dir $@)
	@which $(CLANG) >/dev/null 2>&1 || \
		(echo "Unable to find clang, Install clang (>=3.7) package"; exit 1)
	$(AM_V_CC) $(CLANG) -O3 -c $< -o - -emit-llvm | \
	$(LLC) -march=bpf - -filetype=obj -o $@


EXTRA_DIST += $(dist_sources) $(dist_headers) $(bpf_extra)
