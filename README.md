# FORKEVER

Forkever is a tool that helps you in analysing and exploiting a program.
It lets you
- fork the inspected program at any given point in time 
- insert function calls whenever you want
- inspect and change the memory with a hexeditor


### install
    pip install pwntools
    git clone https://github.com/haxkor/forkever
    chmod +x forkever/forkever.py
    gcc -o forkever/launcher/launcher -g -no-pie forkever/launcher/launcher.c
    
    git clone https://github.com/haxkor/hyx4forkever
    gcc -o hyx4forkever/hyx -pthread hyx4forkever/*.c
    
    
Forkever makes use of (a slightly modified) python-ptrace.
The Author of this library recommends to install the binding of ptrace *"for faster debug and to avoid ctypes"*, although it is not necessary. 

    cd forkever/installCptrace
    python3 setup_cptrace.py
    
### usage
Lauch Forkever:

    ./forkever -rand -init init_file_example echo "hello" "bye"
    
    
In the application, enter "?" for a list of commands



You can adjust behavior further by fiddling in *Constants.py*

# B U G S ?

~~Incase~~ Once you find them, please open up an issue on Github 
or send me a mail to *jasper.ruehl@tum.de* 
   
## small demo

    root@root> /forkever.py demo/vuln
    type ? for help
    b main
    c
    hit breakpoint at 0x5555555557af
    si
    RIP = main + 0x1
    malloc 1337
    malloc returned 0x555555559260
    fork aftermalloc
    switched to 7832
    RIP = main + 0x1
    free $rax+31337
    [ERR] b'free(): invalid pointer\r\n'
    fork tryagain
    switched to 7854
    RIP = main + 0x1
    free 0x555555559260
    free returned 0x0
    c
    process requests 31 bytes from stdin
    no data to stdin was provided
    [OUT] b'1. malloc\r\n2. realloc\r\n3. free\r\n4. calloc\r\n5. aligned_alloc\r\n6. posix_memalign\r\n7. read\r\n8. write\r\n9. exit\r\n> '
    tree
    7813  (aftermallocp)
    |-- 7832  (aftermalloc)
    +-- 7854  (tryagain)

    switch up
    switched to 7813
    RIP = main + 0x1
    c
    hyx stack rwp [i:i]
   
    
    

    
    

    
