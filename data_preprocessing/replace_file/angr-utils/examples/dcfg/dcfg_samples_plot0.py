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
import random
if __name__ == "__main__":
    catalog = "./samples0/"
    fail_dir = "./fail_sample/"
    succ_dir = "./succ_sample/"
    files = os.listdir(catalog)
    print('the followings will be run '+str(files))
    random.shuffle(files)
    for f in files:
        executable = f
        print('\n========================\n'+executable + ' is running.......') 
        try:    
            proj = angr.Project(catalog+executable, load_options={'auto_load_libs':False})
            print(proj.arch.name)           
            print('SCFG-----------------pass')
            time0 = time.clock()
            #cfg_fast = proj.analyses.CFG()
            time1 = time.clock()
            #a=(cfg_fast.graph).nodes()

            #print('SCFG with %d nodes and used %d time' %(len(a),time1-time0))
            print('DCFG---------------------')

            time0 = time.clock()
            cfg_slow = proj.analyses.CFGEmulated(fail_fast=False, context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=True)
            time1 = time.clock()

            b=(cfg_slow.graph).nodes()
            print('DCFG with %d nodes and used %d time' %(len(b),time1-time0))

            plot_cfg(proj,cfg_slow, "DCFG_%s_" % (executable), asminst=True, vexinst=False,comments=True, debug_info=False,  remove_imports=False, remove_path_terminator=True)
            print(executable + ' is running successfully.......\n========================')
            # os.system('cp %s %s' % (catalog+f, succ_dir+f))
            if catalog =='./samples0/':
                os.remove(catalog+f)
                pass
        
        except:# TypeError as e:
            print(executable + ' is running failed.......\n========================')  
            #os.system('cp %s %s' % (catalog+f, fail_dir+f))
            if catalog =='./samples0/':
                os.remove(catalog+f)        
                pass
        
        



    