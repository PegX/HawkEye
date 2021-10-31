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
def analyze(b, name=None):
    
    '''
    main = proj.loader.main_object.get_symbol("main")
    addr=main.rebased_addr
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    with hook0(b):
        for addr,func in proj.kb.functions.items():
            pass#print(func)
    with hook0(b):
        cfg_emulated = b.analyses.CFGEmulated(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)
    #cfg = cfg_fast
    
    for addr,func in proj.kb.functions.items():
        print(func.name)
        if func.name in ['main','verify']:
            plot_cfg(b,cfg_fast, "%s_%s_cfg" % (name, func.name), asminst=True, vexinst=True, func_addr={addr:True}, 
            debug_info=False, remove_imports=True, remove_path_terminator=True)
    '''
   
    
    #print(len(cfg_fast.graph.nodes()))
    #A = cfg_fast.graph

    #B = cfg_emulated.graph
    #A = nx.nx_agraph.to_agraph(cfg_fast.graph)
    #Gout = A
    #nx.write_adjlist(Gout,name+"_nx.adjlist")
    #print(list(Gout.nodes()))
    #nx.drawing.nx_agraph.write_dot(Gout,name+"_nx_original.dot")
    
    
    #pos = nx.spring_layout(Gout)
    #nx.draw(Gout)
    '''
    plot_cfg(cfg, "%s_cfg_classic" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
    plot_cfg(cfg, "%s_cfg_classic" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True, format="raw")
    
    for style in ['thick', 'dark', 'light', 'black', 'kyle']:
        set_plot_style(style)
        plot_cfg(cfg, "%s_cfg_%s" % (name, style), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
    '''
class InputTimeourError(Exception):
    pass

def interrupted(signum,frame):
    raise InputTimeourError

if __name__ == "__main__":
    catalog = "./samples0/"
    fail_dir = "./fail_sample/"
    succ_dir = "./succ_sample/"
    files = os.listdir(catalog)
    print('the followings will be run '+str(files))
    scfg_time = []
    dcfg_time = []
    file_size = []

    for f in os.listdir(catalog):
        executable = f

        fsize = os.path.getsize(catalog+executable)
        #fsize = fsize/float(1024)
        filesize=round(fsize,2)
        print('\n========================\n'+executable + ' is running.......') 
        f2o = open('./time_scfg_dcfg.txt','a+')

        try:
            proj = angr.Project(catalog+executable, load_options={'auto_load_libs':False})
            print(proj.arch.name)           
            print('SCFG---------------------')
            signal.signal(signal.SIGALRM,interrupted)
            signal.alarm(100)
            
            time0 = time.time()
            try:
                cfg_fast = proj.analyses.CFG()
            except InputTimeourError:
                print("SCFG timeout error")
                f2o.close

                b=a

            time1 = time.time()
            a=(cfg_fast.graph).nodes()
            scfg_time_tmp=float(time1-time0)
            print('SCFG with %d nodes and used %f time' %(len(a),scfg_time_tmp))
            '''
            print('DCFG---------------------')

            time0 = time.time()
            signal.alarm(100)
            try:
                #cfg_slow = proj.analyses.CFGEmulated(fail_fast=False, context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=True)
            except InputTimeourError:
                print("DCFG timeout error")
                f2o.close

                a=b
            time1 = time.time()
            
            b=(cfg_slow.graph).nodes()
            dcfg_time_tmp = float(time1-time0)
            print('DCFG with %d nodes and used %f time' %(len(b),dcfg_time_tmp))
            f2o.writelines(str(scfg_time_tmp)+'\t'+str(dcfg_time_tmp)+'\t'+str(filesize))
            f2o.close

            print(str(scfg_time_tmp)+'\t'+str(dcfg_time_tmp)+'\t'+str(filesize))

            f2o.writelines('\n')

            '''
            plot_cfg(proj,cfg_fast, "SCFG_%s" % (executable), asminst=True, vexinst=False,comments=True, debug_info=False,  remove_imports=False, remove_path_terminator=True)
            print(executable + ' is running successfully.......\n========================')
            os.system('cp %s %s' % (catalog+f, succ_dir+f))
            if catalog =='./samples0/':
                os.remove(catalog+f)
                pass
        
        except:# TypeError as e:
            print(executable + ' is running failed.......\n========================')  
            f2o.close

            os.system('cp %s %s' % (catalog+f, fail_dir+f))
            if catalog =='./samples0/':
                #os.remove(catalog+f)        
                pass
    '''
    with open('time_scfg_dcfg.txt', 'r') as f:
        lines = f.readlines()
        for line in lines:
            data2read=line.split()
            scfg_time.append(float(data2read[0]))
            dcfg_time.append(float(data2read[1]))
            file_size.append(float(data2read[2]))
    f1 = plt.figure(1)
    plt.scatter(file_size,scfg_time,c='red', alpha=0.6)
    plt.savefig("time_result_scfg.png") 
    
    f2 = plt.figure(2)
    plt.scatter(file_size,dcfg_time,c='green', alpha=0.6)  
    plt.savefig("time_result_dcfg.png") 

    plt.show
    '''