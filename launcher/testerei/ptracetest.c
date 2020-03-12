#include <sys/ptrace.h>
#include <sys/mman.h>

#include <stdio.h>

int main(){

    printf("seize value= %#x\n", PTRACE_SEIZE);
    printf("interrupt value= %#x\n", PTRACE_INTERRUPT);


    printf("getmsg value=%#x\n", PTRACE_GETEVENTMSG);
    printf("EVENT_STOP value=%#x\n", PTRACE_EVENT_STOP);

    printf("PTRACE_O_TRACEFORK=%#x\n",PTRACE_O_TRACEFORK);
    printf("PTRACE_O_TRACEVFORK=%#x\n", PTRACE_O_TRACEVFORK);
    printf("PTRACE_O_TRACEEXEC=%#x\n", PTRACE_O_TRACEEXEC);


    printf("MAP value= %#x\n", MAP_PRIVATE);

    printf("MAP_ANON value= %#x\n", MAP_ANONYMOUS);

}
