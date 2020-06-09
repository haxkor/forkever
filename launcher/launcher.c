#include <unistd.h>
#include <stdio.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <stdlib.h>

#define NO_CHANGE 0xffffffff

volatile int go=0;
volatile int current_personality=0;
volatile int add_personality= NO_CHANGE;

int main(int argc, char** argv){
    struct rlimit rlim;
    int ret= getrlimit(RLIMIT_NPROC, &rlim);    

    if (ret){
        perror("getrlimit");
        exit(1);
    }

    rlim.rlim_cur = rlim.rlim_max;
    ret = setrlimit(RLIMIT_NPROC, &rlim);

    //printf("flag= %x\n", ADDR_NO_RANDOMIZE);

    current_personality=personality(NO_CHANGE);
    while( add_personality == NO_CHANGE){}
    personality(current_personality | add_personality);

    //puts("go");
    execve(argv[1],argv + 1,0);
}

