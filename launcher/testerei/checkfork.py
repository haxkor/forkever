import subprocess

with open("forklog","w") as f:

    p=subprocess.Popen("./a.out",stdout=f)
    print(hex(p.pid))

f=open("forklog","r")
out= f.read(10)

print("out=", out)

