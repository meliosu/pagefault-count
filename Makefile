all: count

count: count.skel.h
	clang -O2 -g -o count count.c -lbpf

count.skel.h: count.bpf.o
	bpftool gen skeleton count.bpf.o > count.skel.h

count.bpf.o:
	clang -O2 -g -target bpf -c count.bpf.c


clean:
	rm count count.bpf.o count.skel.h
