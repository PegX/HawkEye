import sys
import os
import subprocess

path = '/home/secyoyo/Documents/angr/angr-dev/angr-utils/examples/cfg_instruction_graph/Viurs_200k_1371_filter/'
path = '/media/secyoyo/Storage/Ubuntu/malware_detection_dcfg/malware_samples/'
path = '/home/secyoyo/Documents/angr/angr-dev/angr-utils/examples/cfg_instruction_graph/fail_sample/virus/'
path = '/home/secyoyo/Documents/angr/angr-dev/angr-utils/examples/cfg_instruction_graph/Virus_64bit_succ/'



tool = 'file '
tool_objdump = 'objdump -d '

for root,dirs,files in os.walk(path):
    count = 0

    for _files_ in files:
        p = subprocess.Popen(tool+path+_files_,shell = True,stdout = subprocess.PIPE) 

        out = p.stdout.readlines()
        out = str(out).split(':')
        print(out[1])
        if '64-bit' in str(out[1]):
                #os.system('mv %s %s' % (path+_files_, pathtomove+_files_))  # 拷文件
                print('=========================================')
                count+=1
    print(count)