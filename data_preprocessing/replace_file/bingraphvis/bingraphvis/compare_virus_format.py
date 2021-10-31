import sys
import os
import subprocess





tool = 'file '
tool_objdump = 'objdump -d '
def find_virus(path):
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

def compare_name(pathexe,pathcfg):
        files1 = os.listdir(pathexe)
        files2 = os.listdir(pathcfg)
        count = 0
        path3 ='/home/secyoyo/Documents/angr/angr-dev/bingraphvis/bingraphvis/dataset32_Intel/'
        for exe in files1:
                p = subprocess.Popen(tool+pathexe+exe,shell = True,stdout = subprocess.PIPE) 
                out = p.stdout.readlines()
                out = str(out).split(':')
                if '32-bit' in str(out[1]):
                        for cfg in files2:
                                if exe+'_cfg_full_y_adj_vector.cfg' == cfg:
                                        print(out[1])
                                        print('find true 64 bits cfg')
                                        count+=1
                                        os.system('cp %s %s' %(pathcfg+cfg,path3+cfg))
        print(count)


if __name__ == "__main__":
       
        pathexe = '/media/secyoyo/Storage/Ubuntu/Virus_all_Intel/'
        pathcfg = '/home/secyoyo/Documents/angr/angr-dev/bingraphvis/bingraphvis/VIRUS32CFG/'
        #find_virus(path00)
        compare_name(pathexe,pathcfg)
