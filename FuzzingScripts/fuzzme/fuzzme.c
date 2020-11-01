#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ALP_START 'a'
#define ALP_SIZE 6
#define STATES_SIZE 10
#define MAX_CHR (ALP_START + ALP_SIZE - 1)



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

#define BUSY_COUNT 0x100000
void busy(){
    for (int i=0; i< BUSY_COUNT; i++){};
}

int is_in_alphabet(char input_char){
    return (input_char >= ALP_START && input_char <= MAX_CHR);
}

int main(){
    char input_char;
    int current_state=1;

    while(1){
        busy();
        if (1> read(STDIN_FILENO, &input_char, 1)) break;

        if (is_in_alphabet(input_char)){
            int prev_state = current_state;
            current_state = trans[current_state][input_char - ALP_START];

            if (current_state){
                trans_counter[ prev_state * ALP_SIZE + (input_char-ALP_START)]++;
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
