#! /usr/bin/env python

import angr
from angrutils import *
    

if __name__ == "__main__":
    name = 'ais3_crackme'
    symbol = "_start"
    proj = angr.Project("../samples/"+name, load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol(symbol)

    start_state = proj.factory.blank_state(addr=main.rebased_addr)
    start_state.stack_push(0x0)
    with hook0(proj):
        #cfg = proj.analyses.CFGEmulated(fail_fast=False,  context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=True)

        pass

    #starts=[main.rebased_addr],
    cfg = proj.analyses.CFG() 
    plot_cg(cfg,proj.kb, "FC_CFG_%s_" % (name), format="dot")
    #plot_cg(cfg,proj.kb, "%s_callgraph_verbose" % name, format="dot", verbose=True)

