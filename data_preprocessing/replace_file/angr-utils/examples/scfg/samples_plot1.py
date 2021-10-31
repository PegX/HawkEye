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
if __name__ == "__main__":
    catalog = "./samples1/"
    fail_dir = "./fail_sample/"
    succ_dir = "./succ_sample/"
    files = os.listdir(catalog)
    random.shuffle(files)     
    print('the followings will be run '+str(files))
    for f in files:
        executable = f
        
        print('\n========================\n'+executable + ' is running.......')
        
        try:
            proj = angr.Project(catalog+executable, load_options={'auto_load_libs':False})
            cfg_fast = proj.analyses.CFG()
            Gout = cfg_fast.graph#nx.nx_agraph.to_agraph(cfg_fast.graph)
            
            #cfg_fast = proj.analyses.CFG(normalize=True)
            plot_cfg(proj,cfg_fast, "SCFG_%s_" % (executable), asminst=True, vexinst=False, debug_info=False,  remove_imports=False, remove_path_terminator=True)
            print(executable + ' is running successfully.......\n========================')
            os.system('cp %s %s' % (catalog+f, succ_dir+f))
            if catalog =='./samples1/':
                os.remove(catalog+f)
        except:# TypeError as e:
            print(executable + ' is running failed.......\n========================')  
            os.system('cp %s %s' % (catalog+f, fail_dir+f))
            if catalog =='./samples1/':
                os.remove(catalog+f)        
                '''
        proj = angr.Project("./samples/"+executable, load_options={'auto_load_libs':False})
        cfg_fast = proj.analyses.CFG()
        #cfg_fast = proj.analyses.CFG(normalize=True)
        plot_cfg(proj,cfg_fast, "%s_cfg_full" % (executable), asminst=True, vexinst=False, debug_info=False,  remove_imports=False, remove_path_terminator=True)
        print(executable + ' is running successfully.......\n========================')
        os.remove(catalog+f)
        '''
        
        



    