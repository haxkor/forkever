 #include <sys/types.h>
#include <unistd.h>

int main(){
    long a=fork();
    puts(&a);

    printf("EAGAIN= %#x",ERESTARTNOINTR);
}

