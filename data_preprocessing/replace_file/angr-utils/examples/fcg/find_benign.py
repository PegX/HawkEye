import sys
import os
import subprocess

path = '/usr/bin/'
path = './sample_succ/'
tool = 'file '
tool_objdump = 'objdump -d '
print("Searching Program Format...")
for root,dirs,files in os.walk(path):
    count = 0
    for _files_ in files:
        p = subprocess.Popen(tool+path+_files_,shell = True,stdout = subprocess.PIPE) 

        out = p.stdout.readlines()
        print(out)

        if '80386' in str(out[0]):
            print("===================\n===================\n")
            count+=1
    print(count)
    print(len(files))
#os.system('cp %s %s' % (path+_files_, '/home/secyoyo/Documents/benign_exe/'+_files_))  # 拷文件
