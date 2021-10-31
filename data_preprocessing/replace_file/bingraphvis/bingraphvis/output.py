import pydot
import networkx as nx
import numpy as np
from subprocess import Popen, PIPE, STDOUT
from .base import Output
import networkx as nx
from .readcfg import readcfg
escape_map = {
    "!" : "&#33;",
    "#" : "&#35;",
    ":" : "&#58;",
    "{" : "&#123;",
    "}" : "&#125;",
    "<" : "&#60;",
    ">" : "&#62;",
    "\t": "&nbsp;",
    "&" : "&amp;",
    "|" : "&#124;",
}

def escape(text):
    return "".join(escape_map.get(c,c) for c in text)

default_node_attributes = {
    'shape'    : 'Mrecord',
#    'shape': 'none',
    'fontname' : 'monospace',
    'fontsize' : '8.0',
}

default_edge_attributes = {
    'fontname' : 'monospace',
    'fontsize' : '8.0',
}


class DotOutput(Output):

    def __init__(self, fname, format='png', show=False, pause=False,graph_type = 'common',angr_plot=False,nx_basic_plot=False,arch_name='Unknown'):
        super(DotOutput, self).__init__()
        self.fname = fname
        self.format = format
        self.show = False
        self.pause = pause
        self.eigenvector = []
        self.nx_cfg_switch = nx_basic_plot
        self.angr_cfg_switch = angr_plot
        self.Label = 1
        self.graph_type = graph_type
        self.cfg_digraph = False
        self.arch_name =arch_name
    def render_attributes(self, default, attrs):
        #print('render_attributes......')

        a = {}
        a.update(default)
        a.update(attrs)
        r = []
        for k,v in a.items():
            r.append(k+"="+v)
        
        return "["+", ".join(r)+"]"

    def render_cell(self,key,data,cfg,nodeindex):
        #print('saving eigenvector!!!!!!!!'+str(nodeindex)+'\n')

        if data != None and data['content'] != None and isinstance(data['content'], list):
            embedding_vector=data['content']
            cfg.add_node(nodeindex,eigenvector=embedding_vector)
            
            ret=''
            self.eigenvector.insert(nodeindex, embedding_vector)

            return ret

        if data != None and data['content'] != None and data['content'].strip() != '':
            ret = '<TD '+ ('bgcolor="'+data['bgcolor']+'" ' if 'bgcolor' in data else '') + ('ALIGN="'+data['align']+'"' if 'align' in data else '' )+'>'
            if 'color' in data:
                ret += '<FONT COLOR="'+data['color']+'">'
            if 'style' in data:
                ret += '<'+data['style']+'>'
            
            #'content': "<TABLE><TR><TD>" +  "</TD></TR><TR><TD>".join(self.cllog[key]) + "</TD></TR></TABLE>",

            if isinstance(data['content'], list):
                #print('finding vector list!!!!!!')
                ret += '<TABLE BORDER="0">'
                for c in data['content']:
                    ret += '<TR><TD ' + ('ALIGN="'+data['align']+'"' if 'align' in data else '' )+'>'
                    ret += escape(c)
                    ret += '</TD></TR>'
                ret += '</TABLE>'
                
            else:
                ret += escape(data['content'])
            if 'style' in data:
                ret += '</'+data['style']+'>'
            if 'color' in data:
                ret += '</FONT>'
            ret += "</TD>"
            return ret
        else:
            return "<TD></TD>"
    
    def render_row(self, row, colmeta,cfg,nodeindex):
        #print('Running render row.....')
        eigenvector=[]
        ret = "<TR>"
        for k in colmeta:
            ret_temp = self.render_cell(k, row[k] if k in row else None,cfg,nodeindex)
            ret += ret_temp
 
        ret += "</TR>"
        return ret
    
    def render_content(self, c,cfg,nodeindex):
        #print('Running render content.....')

        ret = ''
        if len(c['data']) > 0:
            ret = '<TABLE BORDER="0" CELLPADDING="1" ALIGN="LEFT">'
            for r in c['data']:
                ret += self.render_row(r, c['columns'],cfg,nodeindex)
            ret += '</TABLE>'
        return ret
        
    def render_node(self, n, CFG):
        #print('Running render node.....')

        attrs = {}
        if n.style:
            attrs['style'] = n.style
        if n.fillcolor:
            attrs['fillcolor'] = '"'+n.fillcolor+'"'
        if n.color:
            attrs['color'] = n.color
        if n.width:
            attrs['penwidth'] = str(n.width)
        if n.url:
            attrs['URL'] = '"'+n.url+'"'
        if n.tooltip:
            attrs['tooltip'] = '"'+n.tooltip+'"'
            
        label = "|".join([self.render_content(c,CFG,n.seq) for c in n.content.values()])
        if label:
            attrs['label'] = '<{ %s }>' % label
        
        #label = '<TABLE ROWS="*" BORDER="1" STYLE="ROUNDED" CELLSPACING="4" CELLPADDING="0" CELLBORDER="0"><TR><TD FIXEDSIZE="FALSE" ALIGN="LEFT">' + '</TD></TR><TR><TD FIXEDSIZE="FALSE"  ALIGN="LEFT">'.join([self.render_content(c) for c in n.content.values()]) + "</TD></TR></TABLE>"
        #if label:
        #    attrs['label'] = '<%s>' % label
        
        CFG.add_node(n.seq,level='basic_block_node')
        return "%s %s" % (str(n.seq), self.render_attributes(default_node_attributes, attrs))

    def render_edge(self, e,CFG):
        #print('Running render edge.....')

        attrs = {}
        if e.color:
            attrs['color'] = e.color
        if e.label:
            attrs['label'] = '"'+e.label+'"'
        if e.style:
            attrs['style'] = e.style
        if e.width:
            attrs['penwidth'] = str(e.width)
        if e.weight:
            attrs['weight'] = str(e.weight)
        CFG.add_edge(e.src.seq,e.dst.seq)
        return "%s -> %s %s" % (str(e.src.seq), str(e.dst.seq), self.render_attributes(default_edge_attributes, attrs))
        
        
    def generate_cluster_label(self, label):
        #print('generate_cluster_label.....')

        rendered = ""
        #CFG=nx.MultiDiGraph()
        if label is None:
            pass
        elif isinstance(label, list):
            rendered = ""
            rendered += "<BR ALIGN=\"left\"/>"
            for l in label:
                rendered += escape(l) 
                rendered += "<BR ALIGN=\"left\"/>"
        else:
            rendered += escape(label)
        
        return 'label=< %s >;' % rendered
        
    def generate_cluster(self, graph, cluster,CFG):
        #print('generate_cluster.....')

        ret = ""

        if cluster:
            ret += "subgraph " + ("cluster" if cluster.visible else "X") + "_" + str(graph.seqmap[cluster.key]) + "{\n"
            ret += self.generate_cluster_label(cluster.label)+"\n"
            if cluster.style:
                ret +='style="%s";\n' % cluster.style
            if cluster.fillcolor:
                ret +='color="%s";\n' % cluster.fillcolor
                
        nodes = list(filter(lambda n:n.cluster == cluster, graph.nodes))
        
        if len(nodes) > 0 and hasattr(nodes[0].obj, 'addr'):
            nodes = sorted(nodes, key=lambda n: n.obj.addr)
        
        for n in nodes:
            ret += self.render_node(n,CFG) + "\n"

        if cluster:
            for child_cluster in graph.get_clusters(cluster):
                ret += self.generate_cluster(graph, child_cluster,CFG)

        if cluster:
            ret += "}\n"
        return ret
        
    def generate(self, graph):
        #print('generating.....')
        CFG = nx.DiGraph()

        ret  = "digraph \"\" {\n"
        ret += "rankdir=TB;\n"
        ret += "newrank=true;\n"
        # for some clusters graphviz ignores the alignment specified in BR
        # but does the alignment based on this value (possible graphviz bug)
        ret += "labeljust=l;\n"
        
        for cluster in graph.get_clusters():
            ret += self.generate_cluster(graph, cluster,CFG)
            
        ret += self.generate_cluster(graph, None,CFG)

        for e in graph.edges:
            ret += self.render_edge(e,CFG) + "\n"
            
        ret += "}\n"
        #print(ret)   
        if self.show:
            p = Popen(['xdot', '-'], stdin=PIPE)
            p.stdin.write(ret)
            p.stdin.flush()
            p.stdin.close()
            if self.pause:
                p.wait()
        data2save=[]
        if self.fname and self.angr_cfg_switch:
            dotfile = XDot(ret)
            dotfile.write("{}.{}".format(self.fname, self.format), format=self.format)
            pass
        A = nx.adjacency_matrix(CFG)
        #self.save_data(A,self.fname+"_adj")
        
        #print(type(A))
        #print(type(A.todense()))
        print('CFG nodes number: %s' % CFG.number_of_nodes())
        if self.nx_cfg_switch:
            nx.drawing.nx_agraph.write_dot(CFG,self.fname+"_nx.dot")
        print('length of eigenvector: %s' % len(self.eigenvector))
        # ==================Vector Saving=======================
        if self.graph_type == 'cfg':
            data2save.append(self.Label)
            data2save.append(A)
            data2save.append(self.eigenvector)
            arch_name=''.join(self.arch_name.split())
            arch_name  =  arch_name.replace('<', "_")
            arch_name  =  arch_name.replace('>', "_")
            arch_name  =  arch_name.replace(')', "")
            arch_name  =  arch_name.replace('(', "")

            self.save_data(data2save,self.fname+arch_name+"_1adjvec")            
            if self.cfg_digraph == True:
                data2save=[]
                # ==================DiGraph Saving=======================
                data2save.append(self.Label)
                data2save.append(CFG)
                self.save_data(data2save,self.fname+"_DiGraph")

        
    def save_data(self,data2save,filename):
        readcfg.save(data2save,filename+".cfg")

class XDot(pydot.Dot):
    def __init__(self, content):
        super(XDot, self).__init__()
        self.content = content
    def to_string(self):
        return self.content
class Graphoutput(Output):
    def __init__(self, fname, format='dot', show=False, pause=False):
        self.fname = fname
        self.format = format
        self.show = show
        self.pause = pause

    def render_attributes(self, default, attrs):
        pass


class DumpOutput(Output):

    def __init__(self):
        super(DumpOutput, self).__init__()

    def generate(self, graph):
        ret = ""
        for e in graph.edges:
            ret += self.render_edge(e) + "\n"

    def render_edge(self, e):
        return "%s %s %s" % (hex(e.src.obj.addr), hex(e.dst.obj.addr), e.meta['jumpkind'])
    