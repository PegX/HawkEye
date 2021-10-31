#! /usr/bin/env python

import angr
from angrutils import plot_cfg, hook0, set_plot_style
import bingraphvis
import networkx as nx
from networkx.readwrite import json_graph
import json
import matplotlib.pyplot as plt
import os
import time
import numpy as np
import matplotlib.pyplot as plt
import eventlet
import signal
import random

class InputTimeourError(Exception):
    pass

def interrupted(signum,frame):
    raise InputTimeourError

if __name__ == "__main__":
    catalog = "./samples0/"
    fail_dir = "./sample_fail/"
    succ_dir = "./sample_succ/"
    files = os.listdir(catalog)
    print('the followings will be run '+str(files))
    scfg_time = []
    dcfg_time = []
    file_size = []
    files2read = os.listdir(catalog)
    random.shuffle(files2read)
    for f in files2read:
        executable = f
        fsize = os.path.getsize(catalog+executable)
        filesize=round(fsize,2)
        print('\n========================\n'+executable + ' is running.......') 
        f2o = open('./time_scfg_dcfg.txt','a+')

        try:
            proj = angr.Project(catalog+executable, load_options={'auto_load_libs':False})
            print(proj.arch.name)           
            print('DCFG---------------------')

            time0 = time.time()
            signal.alarm(300)
            try:
                cfg_slow = proj.analyses.CFGEmulated(fail_fast=False, context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=True)
            except InputTimeourError:
                print("DCFG timeout error")
                f2o.close
                print(executable + ' is running failed at DCFG.......\n========================')  
                os.system('mv %s %s' % (catalog+f, fail_dir+f))
                continue
            time1 = time.time()
            
            b=(cfg_slow.graph).nodes()
            dcfg_time_tmp = float(time1-time0)
            
            print('DCFG with %d nodes and used %f time' %(len(b),dcfg_time_tmp))

            print('SCFG---------------------')
            signal.signal(signal.SIGALRM,interrupted)
            signal.alarm(600)
            '''
            time0 = time.time()
            try:
                cfg_fast = proj.analyses.CFG()
            except InputTimeourError:
                print("SCFG timeout error")
                f2o.close
                print(executable + ' is running failed at SCFG.......\n========================')  
                os.system('mv %s %s' % (catalog+f, fail_dir+f))
                continue

            time1 = time.time()
            a=(cfg_fast.graph).nodes()
            scfg_time_tmp=float(time1-time0)
            print('SCFG with %d nodes and used %f time' %(len(a),scfg_time_tmp))
            print(str(scfg_time_tmp)+'\t'+str(dcfg_time_tmp)+'\t'+str(filesize))
            '''
            time0 = time.time()
            #cfg generating
            plot_cfg(proj,cfg_slow, "DCFG_%s_" % (executable), asminst=True, vexinst=False,comments=True, debug_info=False,  remove_imports=False, remove_path_terminator=True)
            time1 = time.time()
            dcfgmnemonic_time_tmp = float(time1-time0)
            '''
            time0 = time.time()
            #cfg generating
            plot_cfg(proj,cfg_fast, "SCFG_%s_" % (executable), asminst=True, vexinst=False,comments=True, debug_info=False,  remove_imports=False, remove_path_terminator=True)
            time1 = time.time()
            scfgmnemonic_time_tmp = float(time1-time0)
            
            f2o.writelines(str(scfg_time_tmp)+'\t'+str(dcfg_time_tmp)+'\t'+str(scfgmnemonic_time_tmp)+'\t'+str(dcfgmnemonic_time_tmp)+'\t'+str(filesize)+'\n')
            '''
            f2o.close

            print(executable + ' is running successfully.......\n========================')
            os.system('mv %s %s' % (catalog+f, succ_dir+f))
            if catalog =='./samples0/':
                #os.remove(catalog+f)
                pass
        
        except:# TypeError as e:
            print(executable + ' is running failed generally.......\n========================')  
            f2o.close

            if catalog =='./samples0/':
                os.system('mv %s %s' % (catalog+f, fail_dir+f))
                pass
    
    with open('time_scfg_dcfg.txt', 'r') as f:
        lines = f.readlines()
        for line in lines:
            data2read=line.split()
            scfg_time.append(float(data2read[0]))
            dcfg_time.append(float(data2read[1]))
            file_size.append(float(data2read[4]))
    f1 = plt.figure(1)
    plt.scatter(file_size,scfg_time,c='red', alpha=0.6)
    plt.savefig("time_result_scfg.png") 
    
    f2 = plt.figure(2)
    plt.scatter(file_size,dcfg_time,c='green', alpha=0.6)  
    plt.savefig("time_result_dcfg.png") 

    plt.show
