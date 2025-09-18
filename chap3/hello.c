#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level
    , const char *format
    , va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

int main(){
    struct hello_bpf *skel;

    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = hello_bpf__open_and_load();
    if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

    err = hello_bpf__attach(skel);
    if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		hello_bpf__destroy(skel);
        return 1;
	}
    

    while(true) {
        
        if(err == -EINTR) {
            err = 0;
            break;
        }

        
    }

    


    hello_bpf__destroy(skel);
    return -err;
}