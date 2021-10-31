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
    catalog = "./samples_test/angr_test/"
    fail_dir = "./fail_sample/"
    succ_dir = "./succ_sample/"
    files = os.listdir(catalog)
    print('the followings will be run '+str(files))
    for f in os.listdir(catalog):
        executable = f
        
        print('\n========================\n'+executable + ' is running.......')
        
        
        p = angr.Project(catalog+executable, load_options={'auto_load_libs':False})
        cfg = p.analyses.CFG()

       
        funcname = p.kb.functions.values()
        for func in p.kb.functions.values():
            print(func.name)

        '''
        entry_node = cfg.get_any_node(p.entry)
        print(entry_node)
        print(len(cfg.get_all_nodes(p.entry)))
        print(entry_node.predecessors)
        print(entry_node.successors)
        print(cfg.kb.functions.function())
        #print(p.factory.block())
        '''       
                
        
        



    