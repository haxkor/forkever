# FORKEVER

Are you tired of countless restarts when studying binary exploitation?

Are you sick of manually inspecting the same memory address over and over again?

Do you have enough of writing the same data to that babyheap challenge's STDIN just to call malloc?

Well then Forkever might be just the right tool for you!

Given a binary that you want to exploit, Forkever is a debugger that lets you
- fork the debugged at any given point in time to create "checkpoints"
- call functions at any time (e.g. "malloc 10" when training heap exploitation)
- view and change the memory in real-time using a hexeditor


Forkever was developed with heap exploitation in mind, and has already assisted students of the BX course at TUM.
Further, it helped with [solving a 0CTF challenge](https://hxp.io/blog/77/0CTF-Finals-2020-babyheap/).


    
##### Launch Forkever:

    ./forkever echo "hello" "bye"
    
Randomisation of addresses is disabled by default, you can reenable it with "-rand"

To save time, you can also pass a file with commands that should be run instantly: "-init path/to/file"
    
##### essential commands:
    
    b <address>  -  set a breakpoint
    c  -  continue execution
    fork <name>  -  fork to create a backup of the process, name is optional
    tree  -  print process tree
    switch <name|pid|"up">  -  switch to another process
    
    call binary:function_name arg0 arg1 arg2  -  call the indicated function
    
    hyx <segment| >  -  view the indicated segment (default: view heap)
    
    
In the application, enter "?" for a list of commands
To learn more about the *hyx* command for example, type "?hyx"



You can adjust behavior further by fiddling in *Constants.py*, but be careful! ;)

## small demo

    root@sudo> /forkever.py demo/vuln
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
    hyx stack [i:i]
   
    
    

 
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
    
    
##### known problems
Forkever does not immediately launch the program you provided. 
Instead, it starts up the "launcher" and starts tracing that launcher.
Once attached, the launcher will start the provided process.
It can happen that Forkever will fail to attach to the process and exit.
The launcher will then be stuck in an infinite loop and eat your CPU.

In this case, find out the PID with *ps aux | grep launcher* and *kill* the process yourself.

    

# B U G S ?

~~Incase~~ Once you find them, please open up an issue on Github 

   