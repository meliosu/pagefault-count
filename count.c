#include <stdio.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "count.skel.h"

__attribute__((noreturn)) static void panic(const char *msg) {
    perror(msg);
    exit(1);
}

static int get_count(unsigned long *cnt, struct bpf_map *map, int idx) {
    return bpf_map__lookup_elem(map, &idx, sizeof(idx), cnt, sizeof(*cnt), 0);
}

static void print_counts(const char *who, unsigned long curr,
                         unsigned long total) {
    printf("%-10s %-10ld %-10ld\n", who, curr, total);
}

int main() {
    struct count_bpf *object = count_bpf__open_and_load();

    if (!object) {
        panic("error opening or loading object");
    }

    if (count_bpf__attach(object) < 0) {
        panic("error attaching");
    }

    struct bpf_map *map = object->maps.faults;

    unsigned long count;

    unsigned long user_count = 0;
    unsigned long kernel_count = 0;

    unsigned long user_total = 0;
    unsigned long kernel_total = 0;

    while (1) {
        printf("..............................\n");
        printf("%-10s %-10s %-10s\n", "who", "faults/s", "total");

        if (get_count(&count, map, 0)) {
            panic("error getting user faults");
        }

        user_count = count - user_total;
        user_total = count;
        print_counts("user", user_count, user_total);

        if (get_count(&count, map, 1)) {
            panic("error getting kernel faults");
        }

        kernel_count = count - kernel_total;
        kernel_total = count;
        print_counts("kernel", kernel_count, kernel_total);

        print_counts("both", user_count + kernel_count,
                     user_total + kernel_total);

        sleep(1);
    }
}
