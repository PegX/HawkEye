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
def analyze(b, name=None):
    
    pass
if __name__ == "__main__":
    catalog = "./samples/"
    fail_dir = "./fail_sample/"
    succ_dir = "./succ_sample/"
    files = os.listdir(catalog)
    random.shuffle(files)
    print('the followings will be run '+str(files))
    for f in files:
        executable = f
        
        print('\n========================\n'+executable + ' is running.......')
        
        try:
            print('project loading...')
            proj = angr.Project(catalog+executable, load_options={'auto_load_libs':False})
            print('CFG Fast generating...')

            cfg_fast = proj.analyses.CFGFast()
            Gout = cfg_fast.graph#nx.nx_agraph.to_agraph(cfg_fast.graph)
            
            #cfg_fast = proj.analyses.CFG(normalize=True)
            print('CFG Plotting...')
            plot_cfg(proj,cfg_fast, "SCFG_%s_" % (executable), asminst=True, vexinst=False, debug_info=False,  remove_imports=False, remove_path_terminator=True)
            print(executable + ' is running successfully.......\n========================')
            os.system('cp %s %s' % (catalog+f, succ_dir+f))
            if catalog =='./samples/':
                os.remove(catalog+f)
        except:# TypeError as e:
            print(executable + ' is running failed.......\n========================')  
            os.system('cp %s %s' % (catalog+f, fail_dir+f))
            if catalog =='./samples/':
                os.remove(catalog+f)        
                '''
        proj = angr.Project("./samples/"+executable, load_options={'auto_load_libs':False})
        cfg_fast = proj.analyses.CFG()
        #cfg_fast = proj.analyses.CFG(normalize=True)
        plot_cfg(proj,cfg_fast, "%s_cfg_full" % (executable), asminst=True, vexinst=False, debug_info=False,  remove_imports=False, remove_path_terminator=True)
        print(executable + ' is running successfully.......\n========================')
        os.remove(catalog+f)
        '''
        
        



    