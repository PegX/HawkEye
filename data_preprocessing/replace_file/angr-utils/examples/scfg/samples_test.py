#! /usr/bin/env python

import angr
from angrutils import plot_cfg, hook0, set_plot_style
import bingraphvis
import networkx as nx
from networkx.readwrite import json_graph
import json
import matplotlib.pyplot as plt
import os

if __name__ == "__main__":
    catalog = "./samples_test/"
    fail_dir = "./fail_sample/"
    succ_dir = "./succ_sample/"
    files = os.listdir(catalog)
    print('the followings will be run '+str(files))
    for f in os.listdir(catalog):
        executable = f
        
        print('\n========================\n'+executable + ' is running.......')
        
        
        proj = angr.Project(catalog+executable, load_options={'auto_load_libs':False})
        cfg_fast = proj.analyses.CFG()
        Gout = cfg_fast.graph#nx.nx_agraph.to_agraph(cfg_fast.graph)
        print(cfg_fast.graph.nodes)
        #cfg_fast = proj.analyses.CFG(normalize=True)
        plot_cfg(proj,cfg_fast, "%s_cfg_full" % (executable), asminst=True, vexinst=False, debug_info=False,  remove_imports=False, remove_path_terminator=True)
        print(executable + ' is running successfully.......\n========================')
            #os.system('cp %s %s' % (catalog+f, succ_dir+f))
            #if catalog =='./samples/':              
		#os.remove(catalog+f)
        
        
        



    
