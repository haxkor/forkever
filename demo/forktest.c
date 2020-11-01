int main(){

    if (fork()){
        puts("true");
    } else {
        puts("false");
    }
}
