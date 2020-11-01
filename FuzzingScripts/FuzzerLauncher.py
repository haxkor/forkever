import subprocess
import resource

soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
soft_filelimit = soft * 256 * 4
resource.setrlimit(resource.RLIMIT_NOFILE, (soft_filelimit, hard))

result = []
ind = 1
seed = 0
for num_gens in range(4,20,5):
    args = "python3 Fuzzer.py %d %d %d" % (ind, num_gens, seed)
    result.append(subprocess.check_output(args.split()))

