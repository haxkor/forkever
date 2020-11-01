#define _POSIX_C_SOURCE 200112L
#define _ISOC11_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

void print_menu() {
    puts("1. malloc");
    puts("2. realloc");
    puts("3. free");
    puts("4. calloc");
    puts("5. aligned_alloc");
    puts("6. posix_memalign");
    puts("7. read");
    puts("8. write");
    puts("9. exit");
}

unsigned long long getull(char *text) {
    char buf[0x20];
    size_t len;
    printf("%s", text);
    len = read(0, buf, sizeof(buf) - 1);
    buf[len] = 0;
    return strtoull(buf, NULL, 0);
}

void perform_malloc() {
    char *ret;
    size_t len = getull("size: ");
    ret = malloc(len);
    fprintf(stderr, "malloc(%#zx) := %p\n", len, ret);
    printf("%p\n", ret);
}

void perform_realloc() {
    char *ptr, *ret;
    size_t len;
    ptr = (char *) getull("pointer: ");
    len = getull("size: ");
    ret = realloc(ptr, len);
    fprintf(stderr, "realloc(%p, %#zx) := %p\n", ptr, len, ret);
    printf("%p\n", ret);
}

void perform_free() {
    char *ptr;
    ptr = (char *) getull("pointer: ");
    free(ptr);
    fprintf(stderr, "free(%p)\n", ptr);
}

void perform_calloc() {
    char *ret;
    size_t nmemb = getull("nmemb: ");
    size_t len = getull("size: ");
    ret = calloc(nmemb, len);
    fprintf(stderr, "calloc(%#zx, %#zx) := %p\n", nmemb, len, ret);
    printf("%p\n", ret);
}

void perform_aligned_alloc() {
    char *ret;
    size_t alignment = getull("alignment: ");
    size_t len = getull("size: ");
    ret = aligned_alloc(alignment, len);
    fprintf(stderr, "aligned_alloc(%#zx, %#zx) := %p\n", alignment, len, ret);
    printf("%p\n", ret);
}

void perform_posix_memalign() {
    int ret;
    void **memptr = (void **) getull("memptr: ");
    size_t alignment = getull("alignment: ");
    size_t len = getull("size: ");
    ret = posix_memalign(memptr, alignment, len);
    fprintf(stderr, "posix_memalign(%p, %#zx, %#zx) := %u\n", (void*) memptr, alignment, len, ret);
    printf("%u\n", ret);
}

void perform_read() {
    char *buf;
    size_t len, ret, tmp;
    buf = (char *) getull("pointer: ");
    len = getull("length: ");
    ret = 0;

    do {
        tmp = read(0, buf, len - ret);
        if (tmp == 0) {
            perror("read");
            exit(1);
        }
        ret += tmp;
    } while (ret < len);

    fprintf(stderr, "read(%p, %#zx) := \"", buf, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02hhx", buf[i]);
    }
    fprintf(stderr, "\"\n");
}

void perform_write() {
    char *buf;
    size_t len;
    buf = (char *) getull("pointer: ");
    len = getull("length: ");

    write(0, buf, len);

    fprintf(stderr, "write(%p, %#zx) := \"", buf, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02hhx", buf[i]);
    }
    fprintf(stderr, "\"\n");
}

void perform_exit() __attribute__((noreturn));
void perform_exit() {
    exit(0);
}

int main () {
    unsigned long long choice;

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    print_menu(1);
    while (1) {
        choice = getull("> ");
        switch(choice) {
        case 1:
            perform_malloc();
            break;
        case 2:
            perform_realloc();
            break;
        case 3:
            perform_free();
            break;
        case 4:
            perform_calloc();
            break;
        case 5:
            perform_aligned_alloc();
            break;
        case 6:
            perform_posix_memalign();
            break;
        case 7:
            perform_read();
            break;
        case 8:
            perform_write();
            break;
        case 9:
            perform_exit();
            break;
        default:
            print_menu();
            break;
        }
    }
}
