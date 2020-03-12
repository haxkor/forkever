#include <malloc.h>

#define N 20

int main(){
    puts("starting testmalloc");

    float junk=0.1f;

    for (volatile int i=0; i<0x1FffFFff;i++){
        junk*= (0.45f-junk);
    }

    puts("after loop");

    

    puts("gonna malloc N");

    int* buf= malloc(sizeof(int) * N);

    printf("buf= %llx",buf);

    for (volatile int i=0; i<0x1FffFFff;i++){
        junk*= (0.45f-junk);
    }


}





    
