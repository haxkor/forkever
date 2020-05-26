#include <unistd.h>
#include <stdio.h>
#include <sys/personality.h>

#define NO_CHANGE 0xffffffff

volatile int go=0;
volatile int current_personality=0;
volatile int add_personality= NO_CHANGE;

int main(int argc, char** argv){

    printf("flag= %x\n", ADDR_NO_RANDOMIZE);

    current_personality=personality(NO_CHANGE);

    while( add_personality == NO_CHANGE){}

    personality(current_personality | add_personality);

    printf("launching\nadd_personality= %#x", add_personality);

    execve(argv[1],argv + 1,0);
}

