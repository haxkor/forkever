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

![Forkever](https://github.com/haxkor/forkever/blob/master/docs/Screenshot1.png?raw=true)

###### video demo
[vimeo](vimeo.com/474336367)
  
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

   