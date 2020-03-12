#include <unistd.h>
#include <stdio.h>

volatile int go=0;

int main(int argc, char** argv){

    while(!go){
        //scanf("%d",&go);
        printf("d\n");

        volatile float junk=0.123;
        for (volatile int i=0; i<0xFFffFF; i++){
            junk=junk*junk*(0.5-junk);
        }
    }

    printf("exited loop");

    execve(argv[1],argv + 1,0);

}

