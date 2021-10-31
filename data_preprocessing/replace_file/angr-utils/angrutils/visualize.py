import networkx as nx

from collections import defaultdict

from bingraphvis import *
from bingraphvis.angr import *
from bingraphvis.angr.x86 import *

def set_plot_style(c):
    set_style(c)

def plot_common(graph, fname, format="dot", type=True):
    vis = AngrVisFactory().default_common_graph_pipeline(type=type)
    vis.set_output(DotOutput(fname, format=format,graph_type='common'))
    vis.process(graph)
    
def plot_cfg(project,cfg, fname, format="dot", state=None, asminst=True, vexinst=False, func_addr=None, remove_imports=True, remove_path_terminator=True, remove_simprocedures=False, debug_info=False, comments=True, color_depth=False):
    vis = Vis()
    vis.set_source(AngrCFGSource())
    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=False, vexinst=vexinst, remove_path_terminator=remove_path_terminator,comments=comments)

    vis.add_content(AngrAsm_YY(project))
    #data=AngrAsm_YY(project)
    #print(data)
    if remove_imports:
        vis.add_transformer(AngrRemoveImports(cfg.project))
    if remove_simprocedures:
        vis.add_transformer(AngrRemoveSimProcedures())
    if func_addr:
        vis.add_transformer(AngrFilterNodes(lambda node: node.obj.function_address in func_addr and func_addr[node.obj.function_address]))
    if debug_info:
        vis.add_content(AngrCFGDebugInfo())
    if state:
        vis.add_edge_annotator(AngrPathAnnotator(state))
        vis.add_node_annotator(AngrPathAnnotator(state))
    if color_depth:
        vis.add_clusterer(AngrCallstackKeyClusterer())
        vis.add_clusterer(ColorDepthClusterer(palette='greens'))
    arch_name = str(cfg.project.arch)
    vis.set_output(DotOutput(fname, format=format,graph_type='cfg',arch_name=arch_name))    
    vis.process(cfg.graph)
    print('plotting cfg process......') 

def plot_func_graph(project, graph, fname, format="dot", asminst=True, ailinst=True, vexinst=False, structure=None, color_depth=False):
    vis = AngrVisFactory().default_func_graph_pipeline(project, asminst=asminst, ailinst=ailinst, vexinst=vexinst)
    if structure:
        vis.add_clusterer(AngrStructuredClusterer(structure))
        if color_depth:
            vis.add_clusterer(ColorDepthClusterer(palette='greens'))
    vis.set_output(DotOutput(fname, format=format,graph_type='common',angr_plot=True))
    vis.process(graph) 

#Note: method signature may be changed in the future
def plot_structured_graph(project, structure, fname, format="dot", asminst=True, ailinst=True, vexinst=False, color_depth=False):
    vis = AngrVisFactory().default_structured_graph_pipeline(project, asminst=asminst, ailinst=ailinst, vexinst=vexinst)
    if color_depth:
        vis.add_clusterer(ColorDepthClusterer(palette='greens'))
    vis.set_output(DotOutput(fname, format=format,graph_type='common'))
    vis.process(structure)

def plot_cg(cfg,kb, fname, format="dot", verbose=False, filter=None,angr_plot=False):
    vis = AngrVisFactory().default_cg_pipeline(kb, verbose=verbose)
    vis.add_content(AngrAsm_YY(cfg.project))

    arch_name = str(cfg.project.arch)
    vis.set_output(DotOutput(fname, format=format,graph_type='cfg',angr_plot=angr_plot,arch_name=arch_name))
    vis.process(kb, filter)
    
    oberschicht_cfg = nx.DiGraph()

    print(vis)
    print('plotting call graph process......')
    

def plot_cdg(cfg, cdg, fname, format="dot", pd_edges=False, cg_edges=True, remove_fakeret=True):
    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=True, vexinst=False, color_edges=False)
    if remove_fakeret:
        vis.add_transformer(AngrRemoveFakeretEdges())
    if pd_edges:
        vis.add_transformer(AngrAddEdges(cdg.get_post_dominators(), color="green", reverse=True))
    if cg_edges:
        vis.add_transformer(AngrAddEdges(cdg.graph, color="purple", reverse=False))
    vis.set_output(DotOutput(fname, format=format,graph_type='common'))
    vis.process(cfg.graph)

def plot_dfg(dfg, fname, format="dot"):
    vis = AngrVisFactory().default_common_graph_pipeline(type=True)
    vis.set_output(DotOutput(fname, format=format,graph_type='common'))
    vis.process(dfg)

#Note: method signature may change in the future
def plot_ddg_stmt(ddg_stmt, fname, format="dot", project=None):
    vis = AngrVisFactory().default_common_graph_pipeline()
    if project:
        vis.add_content(AngrAsm(project))
        vis.add_content(AngrVex(project))
    vis.add_edge_annotator(AngrColorDDGStmtEdges(project))
    vis.set_output(DotOutput(fname, format=format,graph_type='common'))
    vis.process(ddg_stmt)

#Note: method signature may change in the future
def plot_ddg_data(ddg_data, fname, format="dot", project=None, asminst=False, vexinst=True):
    vis = Vis()
    vis.set_source(AngrCommonSource())
    vis.add_content(AngrDDGLocationHead())
    vis.add_content(AngrDDGVariableHead(project=project))

    if project:
        if asminst:
            vis.add_content(AngrAsm(project))
        if vexinst:
            vis.add_content(AngrVex(project))
    acd = AngrColorDDGData(project, labels=True)
    vis.add_edge_annotator(acd)
    vis.add_node_annotator(acd)
    vis.set_output(DotOutput(fname, format=format,graph_type='common'))
    vis.process(ddg_data)
