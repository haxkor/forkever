#!/bin/bash
x=1
while [ $x -le 10 ]
do
    python3 bench1.py 10001 44444
    sleep 2s
    x=$(( $x + 1 ))
done
