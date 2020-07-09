#include <stdio.h>
#include <stdlib.h>

#define ALP_START 'a'
#define ALP_SIZE 6
#define STATES_SIZE 10
#define MAX_CHR (ALP_START + ALP_SIZE - 1)
#define BUSY_COUNT 0x90000

int trans[][7] = {
{ 0, 0, 0, 0, 0, 0, 0, },
{ 2, 2, 2, 0, 0, 0, 0, },
{ 1, 0, 0, 2, 3, 0, 0, },
{ 4, 6, 0, 0, 0, 0, 0, },
{ 0, 5, 0, 0, 0, 0, 0, },
{ 0, 0, 0, 0, 6, 0, 0, },
{ 0, 0, 7, 7, 0, 0, 0, },
{ 1, 1, 0, 0, 0, 8, 0, }};



int trans_counter[STATES_SIZE * ALP_SIZE];
int count_edges(){
    int result= 0;
    for (int i=0; i< sizeof(trans_counter); i++){
        if (trans_counter[i])
            result++;
    }
    return result;
}

void busy(){
    for (volatile int i=0; i< BUSY_COUNT; i++){};
    return;
}


int main(){
    int input;
    int current_state=1;

    while(input= fgetc(stdin)){
        busy();


        char input_char = (char) input;

        if ( input_char >= ALP_START && input_char <= MAX_CHR){
            int prev_state = current_state;
            current_state = trans[current_state][input - ALP_START];

            if (current_state){
                trans_counter[ prev_state * ALP_SIZE + (input-ALP_START)]++;
            } else {
                //printf("%c entering error", input);
                //break;
            }

        } else {
            //printf("%c invalid", input);
            break;
        }
    }

    printf(",%d.", count_edges());
    exit(0);
}
