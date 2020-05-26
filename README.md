
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
   
   
    
    

    
    

    
