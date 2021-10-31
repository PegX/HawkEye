#! /usr/bin/env python

import angr
from angrutils import plot_cfg, hook0, set_plot_style
import bingraphvis
import networkx as nx
from networkx.readwrite import json_graph
import json
import matplotlib.pyplot as plt
import os
import random

if __name__ == "__main__":
    catalog = "./samples1/"
    fail_dir = "./fail_sample/"
    succ_dir = "./succ_sample/"
    files = os.listdir(catalog)
    print('the followings will be run '+str(files))
    for f in random.shuffle(os.listdir(catalog)):
        executable = f
        
        print('\n========================\n'+executable + ' is running.......')
        
        try:
            proj = angr.Project(catalog+executable, load_options={'auto_load_libs':False})
            cfg_fast = proj.analyses.CFG()
            Gout = cfg_fast.graph#nx.nx_agraph.to_agraph(cfg_fast.graph)
            cfg_slow = proj.analyses.CFGEmulated(fail_fast=False, context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=True)

            #cfg_fast = proj.analyses.CFG(normalize=True)
            plot_cfg(proj,cfg_slow, "%s_dcfg_embedding" % (executable), asminst=True, vexinst=False, debug_info=False,  remove_imports=False, remove_path_terminator=True)
            print(executable + ' is running successfully.......\n========================')
            '''
            os.system('cp %s %s' % (catalog+f, succ_dir+f))
            if catalog =='./samples1/':
                os.remove(catalog+f)
            '''
        except:# TypeError as e:
            print(executable + ' is running failed.......\n========================')  
            '''
            os.system('cp %s %s' % (catalog+f, fail_dir+f))
            if catalog =='./samples1/':
                os.remove(catalog+f)        
            '''
  
        



    