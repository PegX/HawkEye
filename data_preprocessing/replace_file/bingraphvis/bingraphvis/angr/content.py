import numpy as np
from ..base import *
import angr
from angr.sim_variable import SimRegisterVariable, SimMemoryVariable, SimTemporaryVariable, SimConstantVariable, SimStackVariable
from . import *
from Dictionary import I2V
import os
from os import path
def safehex(val):
    return str(hex(val) if val != None else None)
        
class AngrCFGHead(Content):
    def __init__(self):
        super(AngrCFGHead, self).__init__('head', ['addr', 'func_addr', 'name', 'attributes'])

    def gen_render(self, n):
        node = n.obj
        attributes=[]
        
        if node.is_simprocedure:
            attributes.append("SIMP")
        if node.is_syscall:
            attributes.append("SYSC")
        if node.no_ret:
            attributes.append("NORET")
        
        n.content[self.name] = {
            'data': [{
                'addr': {
                    'content': "{:#08x}".format(node.addr),
                },
                'func_addr' : {
                    'content': "({:#08x})".format(node.function_address),
                },
                'name': {
                    'content': node.name, 
                    'style':'B'
                },
                'attributes': {
                    'content': ' '.join(attributes)
                }
            }], 
            'columns': self.get_columns()
        }

class AngrFGraphHead(Content):
    def __init__(self):
        super(AngrFGraphHead, self).__init__('head', ['type', 'name', 'addr'])

    def gen_render(self, n):
        node = n.obj
        node_type = None
        node_color = None
        node_name = None

        # FGraph
        if type(node).__name__ == 'BlockNode':
            node_type = "Block"
        elif type(node).__name__ == 'HookNode':
            node_type = "Hook"
            node_color = "lightblue"
        elif type(node).__name__ == 'Function':
            node_type = "Function"
            node_color = "green"
            node_name = node.name

        #AIL block
        #FIXME
        elif type(node).__name__ == 'Block':
            node_type = "AILBlock"

        else:
            node_type = "Unhandled (%s)" % node.__class__
            node_color = "yellow"
        
        if node_color:
            n.style = 'filled'
            n.fillcolor = node_color
            
        n.content[self.name] = {
            'data': [{
                'type': {
                    'content': node_type
                },
                'name': {
                    'content': node_name
                },
                'addr': {
                    'content': "{:#08x}".format(node.addr),
                    'style':'B'
                },
            }], 
            'columns': self.get_columns()
        }


class AngrCGHead(Content):
    def __init__(self):
        super(AngrCGHead, self).__init__('head', ['name','addr'])
        
    def gen_render(self, n):
        n.content[self.name] = {
            'data': [{
                'addr': {
                    'content': "("+hex(n.obj.addr)+")"
                },
                'name': {
                    'content': n.obj.name,
                    'style':'B'
                }
            }], 
            'columns': self.get_columns()
        }

class AngrCommonHead(Content):
    def __init__(self):
        super(AngrCommonHead, self).__init__('head', ['name'])
        
    def gen_render(self, n):
        if hasattr(n.obj, 'name'):
            name = n.obj.name
        else:
            name = str(n.obj)
        
        n.content[self.name] = {
            'data': [{
                'name': {
                    'content': name
                }
            }], 
            'columns': self.get_columns()
        }

class AngrCommonTypeHead(Content):
    def __init__(self):
        super(AngrCommonTypeHead, self).__init__('headtype', ['name'])
        
    def gen_render(self, n):
        node = n.obj
        n.content[self.name] = {
            'data': [{
                'name': {
                    'content': str(type(node).__name__)
                }
            }], 
            'columns': self.get_columns()
        }

class AngrDDGLocationHead(Content):
    def __init__(self):
        super(AngrDDGLocationHead, self).__init__('head_location', ['name'])
        
    def gen_render(self, n):
        node = n.obj
        label = None
        if node.location.sim_procedure:
            label = "%s" % node.location.sim_procedure
        else:
            label = "%s %s %s %c\n" % ( hex(node.location.ins_addr), hex(node.location.block_addr), str(node.location.stmt_idx), '+' if node.initial else '-')

        n.content[self.name] = {
            'data': [{
                'name': {
                    'content': label
                }
            }], 
            'columns': self.get_columns()
        }

class AngrDDGVariableHead(Content):
    def __init__(self, project=None):
        super(AngrDDGVariableHead, self).__init__('head_variable', ['name'])
        self.project = project
        
    def gen_render(self, n):
        node = n.obj
        try:
            if isinstance(node.variable, SimRegisterVariable):
                if self.project:
                    if node.variable.reg in self.project.arch.register_names:
                        label = "REG %s %d" % (self.project.arch.register_names[node.variable.reg], node.variable.size)
                    else:
                        label = "*REG %s %d" % (node.variable.reg, node.variable.size)
                else:
                    label = "*REG %d %d" % (node.variable.reg, node.variable.size)
            elif isinstance(node.variable, SimMemoryVariable):
                label = "MEM " + str(node.variable) + " " + hex(node.variable.addr)
            elif isinstance(node.variable, SimTemporaryVariable):
                label = "TEMP " + str(node.variable)
            elif isinstance(node.variable, SimConstantVariable):
                label = "CONST" + str(node.variable)
            elif isinstance(node.variable, SimStackVariable):
                label = "STACK" + str(node.variable)
            else:
                label = "UNKNOWN" + str(node.variable)
        except:
            label = "EXCEPTION"
        
        n.content[self.name] = {
            'data': [{
                'name': {
                    'content': label
                }
            }], 
            'columns': self.get_columns()
        }

class AngrAsm_YY(Content):
    def __init__(self, project):
        super(AngrAsm_YY, self).__init__('asm', ['addr', 'mnemonic', 'operands'])
        self.project = project
        print('Running Youyi-ASSEBM Decoing Engine for %s Architecture......'%project.arch)
        self.count = 1
        d = path.dirname(__file__)
        d=os.path.dirname(d)
        d=os.path.dirname(d)
        print(d)
        self.embedding = np.load(d+"/embedding_matrx.npy",allow_pickle=True)
        self.embedding = self.embedding.tolist()
        self.instructionsname = np.load(d+"/dictionary.npy",allow_pickle=True)
        self.embedding_size = 32
        self.instructionsname = self.instructionsname.tolist()
        self.defaultvector = self.embedding[0]
        self.output_vector=False
    def return_name(self,name):
        print('Program ends because of ' +name)   

    def gen_render(self, n):
        i2v = I2V
        Instruction_list=[]
        data_YY = []
        embedding_vector=self.defaultvector 
        data = []
        node = n.obj
        #AngrAsm_YY.cleartxt(self)
        #CFG
        #print(str(type(node).__name__)+'\t\t'+str(node.addr))
        #is_simprocedure = False
        if type(node).__name__ == 'CFGNode' or type(node).__name__ == 'CFGNodeA':
            is_syscall = node.is_syscall
            is_simprocedure = node.is_simprocedure
            addr = node.addr
            size = None
            max_size = node.size
        # DDG
        elif type(node).__name__ == 'CodeLocation':
            is_syscall = False
            is_simprocedure = node.sim_procedure != None
            addr = node.ins_addr
            size = 1
            max_size = None
        elif type(node).__name__ == 'ProgramVariable':
            is_syscall = False
            is_simprocedure = node.location.sim_procedure != None
            addr = node.location.ins_addr
            max_size = None
            size = 1
        # FGgraph
        elif type(node).__name__ == 'BlockNode':
            is_syscall = False
            is_simprocedure = False
            addr = node.addr
            max_size = node.size
            size = None
        elif type(node).__name__ == 'HookNode':
            data=self.add_vector(data,None)
            data=self.add_ins(data,Instruction_list)

            n.content[self.name] = {
                'data': data,
                'columns': self.get_columns(),
            } 
            self.return_name('HookNode')
            return
        elif type(node).__name__ == 'Function':

            addr = node.addr
            size = None
            max_size = node.size
            insns = self.project.factory.block(addr=addr, size=max_size, num_inst=size).capstone.insns
            #print(insns)
            for ins in insns:
                data.append({
                    'addr': {
                        'content': "0x%08x:\t" % ins.address,
                        'align': 'LEFT'
                    },
                    'mnemonic': {
                        'content': ins.mnemonic,
                        'align': 'LEFT'
                    },
                    'operands': {
                        'content': ins.op_str,
                        'align': 'LEFT'
                    },
                    '_ins': ins,
                    '_addr': ins.address
                })
                Instruction_list.append(ins.mnemonic)
            if self.output_vector==True:
                embedding_vector = self.calculate_embedding(Instruction_list)
                data=self.add_vector(data,embedding_vector)
            else:
                data=self.add_ins(data,Instruction_list)

            n.content[self.name] = {
                'data': data,
                'columns': self.get_columns(),
            }
             
            #self.return_name('Function')
            return
        # AIL
        elif type(node).__name__ == 'Block':
            addr = node.addr
            max_size = None
            size = None
            is_syscall = False
            is_simprocedure = False
            self.return_name('Block')
            return
        elif type(node).__name__ == 'CFGENode':
            is_syscall = node.is_syscall
            is_simprocedure = node.is_simprocedure
            addr = node.addr
            size = None
            max_size = node.size
        else:
            if self.output_vector==True:
                data=self.add_vector(data,None)
            else:
                data=self.add_ins(data,None)

            n.content[self.name] = {
                'data': data,
                'columns': self.get_columns(),
            }
            self.return_name('Other Situaions')
            return
        
        

        if is_simprocedure or is_syscall:
            #print(addr)
            max_size = None
            Instruction_list=['jmp','push','jmp']
            for ins in Instruction_list:
                data.append({
                    
                    'mnemonic': {
                        'content': ins,
                        'align': 'LEFT'
                    }
                })

            #print(embedding_vector)
            if self.output_vector==True:
                embedding_vector = self.calculate_embedding(Instruction_list)
                data=self.add_vector(data,embedding_vector)
            else:
                data=self.add_ins(data,Instruction_list)

            n.content[self.name] = {
                'data': data,
                'columns': self.get_columns(),
            }
            #print('is_simprocedure') 
            return
        try:
            insns = self.project.factory.block(addr=addr, size=max_size, num_inst=size).capstone.insns
        except Exception as e:
            print('================unresolvable function=================')
            print(e)
            #TODO add logging
            insns = []
            if self.output_vector==True:
                data=self.add_vector(data,None)
            else:
                data=self.add_ins(data,None)

            n.content[self.name] = {
                'data': data,
                'columns': self.get_columns(),
            }
            self.return_name('unresolvable')
            return    
        #==========================instrucions list===============================#
        #print(insns)

        #self.instructionsdict = dict(zip(instructionsname,embedding))
        #out_list_file = open('/home/secyoyo/Documents/angr/angr-dev/angr-utils/examples/cfg_instruction_graph/log.txt','a')
        
        for ins in insns:
            data.append({
                'addr': {
                    'content': "0x%08x:\t" % ins.address,
                    'align': 'LEFT'
                },
                'mnemonic': {
                    'content': ins.mnemonic,
                    'align': 'LEFT'
                },
                'operands': {
                    'content': ins.op_str,
                    'align': 'LEFT'
                },
                '_ins': ins,
                '_addr': ins.address
            })
            Instruction_list.append(ins.mnemonic)
    
        #print(embedding_average) 
        embedding_vector = self.calculate_embedding(Instruction_list)
        if self.output_vector==True:
            data=self.add_vector(data,embedding_vector)
        else:
            data=self.add_ins(data,Instruction_list)
        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
        }
        #print(data_YY)
        return
    def calculate_embedding(self,Instruction_list):
        #print(Instruction_list)
        a=np.zeros((1,self.embedding_size))
        embedding_average=np.zeros((1,self.embedding_size))
        for Instructions in Instruction_list:
            self.instructionsname.setdefault(Instructions,0)
            index=self.instructionsname[str(Instructions)]

            if index == 0:
                Instructions = (Instructions)[:-1]
                self.instructionsname.setdefault(Instructions,0)
                index=self.instructionsname[str(Instructions)]
                
            a = self.embedding[int(index)]
            #c = (I2V.I2V_Func(self,Instructions))
            embedding_average=embedding_average+a
        #print(embedding_average) 
        #print('==========='+str(len(Instruction_list)))
        if len(Instruction_list)>0:
            lens_Instruction = len(Instruction_list)
        else:
            #print(len(Instruction_list))
            lens_Instruction = 1

        embedding_average=np.divide(embedding_average,(lens_Instruction))
        embedding_vector = embedding_average[0].tolist()
        #print(embedding_vector)
        return embedding_vector

    def add_vector(self,data,embedding_vector_input):
        if embedding_vector_input == None :
            embedding_vector_input = self.defaultvector
        data1=[]
        data1.append({
                #'addr': {
                #    'content': 'Eigenvector',
                #    'align': 'LEFT'
                #},                
                'operands': {
                    'content':embedding_vector_input,
                    'align': 'LEFT'
                    },
                'eigenvector' : {
                    'content': '%s' %  embedding_vector_input,
                }
                #'mnemonic': {
                #'content': ins.mnemonic,
                #'align': 'LEFT'
                #}
                })
        return data

    def add_ins(self,data,Instruction_list):
        if Instruction_list == None :
            Instruction_list = ['UNK']
        data.append({
                #'addr': {
                #    'content': 'Eigenvector',
                #    'align': 'LEFT'
                #},                
                'operands': {
                    'content':Instruction_list,
                    'align': 'LEFT'
                    },
               
                })
        return data



class AngrAsm(Content):
    def __init__(self, project):
        super(AngrAsm, self).__init__('asm', ['addr', 'mnemonic', 'operands'])
        self.project = project        
        self.count = 1
    def gen_render(self, n):
        node = n.obj
        
        #CFG
        if type(node).__name__ == 'CFGNode' or type(node).__name__ == 'CFGNodeA':
            is_syscall = node.is_syscall
            is_simprocedure = node.is_simprocedure
            addr = node.addr
            size = None
            max_size = node.size
        # DDG
        elif type(node).__name__ == 'CodeLocation':
            is_syscall = False
            is_simprocedure = node.sim_procedure != None
            addr = node.ins_addr
            size = 1
            max_size = None
        elif type(node).__name__ == 'ProgramVariable':
            is_syscall = False
            is_simprocedure = node.location.sim_procedure != None
            addr = node.location.ins_addr
            max_size = None
            size = 1
        # FGgraph
        elif type(node).__name__ == 'BlockNode':
            is_syscall = False
            is_simprocedure = False
            addr = node.addr
            max_size = node.size
            size = None
        elif type(node).__name__ == 'HookNode':
            return
        elif type(node).__name__ == 'Function':
            return
        # AIL
        elif type(node).__name__ == 'Block':
            addr = node.addr
            max_size = None
            size = None
            is_syscall = False
            is_simprocedure = False
        else:
            return

        if is_simprocedure or is_syscall:
            return None

        try:
            insns = self.project.factory.block(addr=addr, size=max_size, num_inst=size).capstone.insns
        except Exception as e:
            print(e)
            #TODO add logging
            insns = []
            print('================unresolvable function=================')
        data = []
        for ins in insns:
            data.append({
                'addr': {
                    'content': "0x%08x:\t" % ins.address,
                    'align': 'LEFT'
                },
                'mnemonic': {
                    'content': ins.mnemonic,
                    'align': 'LEFT'
                },
                'operands': {
                    'content': ins.op_str,
                    'align': 'LEFT'
                },
                '_ins': ins,
                '_addr': ins.address
            })

        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
        }    


    

    def cleartxt(self):
        out_list_file = open('/home/secyoyo/Documents/angr/angr-dev/angr-utils/examples/cfg_instruction_graph/log.txt','r+')
        out_list_file.seek(0)
        out_list_file.truncate()
        out_list_file.close()

class AngrAIL(Content):
    def __init__(self, project):
        super(AngrAIL, self).__init__('ail', ['addr', 'stmt'])
        self.project = project        

    def gen_render(self, n):
        node = n.obj
        
        #CFG
        if not type(node).__name__ == 'Block':
            return

        data = []
        for i, stmt in enumerate(node.statements):
            data.append({
                'addr': {
                    'content': "%02d | %x " % (i, stmt.ins_addr),
                    'align': 'LEFT'
                },
                'stmt': {
                    'content': str(stmt),
                    'align': 'LEFT'
                },
                '_stmt': stmt,
                '_addr': stmt.ins_addr
            })

        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
        }



class AngrVex(Content):
    def __init__(self, project):
        super(AngrVex, self).__init__('vex', ['addr', 'statement'])
        self.project = project        

    def gen_render(self, n):
        node = n.obj
        
        #CFG
        if type(node).__name__ == 'CFGNode' or type(node).__name__ == 'CFGNodeA':
            is_syscall = node.is_syscall
            is_simprocedure = node.is_simprocedure
            addr = node.addr
            size = None
            size = node.size
            stmt_idx = None
        elif type(node).__name__ == 'CodeLocation':
            is_syscall = False
            is_simprocedure = node.sim_procedure != None
            addr = node.block_addr
            size = None
            stmt_idx = node.stmt_idx
        elif type(node).__name__ == 'ProgramVariable':
            is_syscall = False
            is_simprocedure = node.location.sim_procedure != None
            addr = node.location.block_addr
            size = None
            stmt_idx = node.location.stmt_idx
        # FGgraph
        elif type(node).__name__ == 'BlockNode':
            is_syscall = False
            is_simprocedure = False
            addr = node.addr
            size = None
            stmt_idx = None
        elif type(node).__name__ == 'HookNode':
            return
        elif type(node).__name__ == 'Function':
            return
        # AIL
        elif type(node).__name__ == 'Block':
            addr = node.addr
            size = None
            is_syscall = False
            is_simprocedure = False
            stmt_idx = None
        else:
            return
            
            
        if is_simprocedure or is_syscall:
            return None

        vex = self.project.factory.block(addr=addr, size=size).vex

        data = []
        for j, s in enumerate(vex.statements):
            if stmt_idx == None or stmt_idx == j:
                data.append({
                    'addr': {
                        'content': "%d:" % j,
                        'align': 'LEFT',
                        'port': str(j)
                    },
                    'statement': {
                        'content': str(s),
                        'align': 'LEFT'
                    },
                    '_stmt': s,
                    '_addr': j
                })
        if stmt_idx == None  or stmt_idx == len(vex.statements):
            data.append({
                'addr': {
                    'content': "NEXT: ",
                    'align': 'LEFT'
                },
                'statement': {
                    'content': 'PUT(%s) = %s; %s' % (vex.arch.translate_register_name(vex.offsIP), vex.next, vex.jumpkind),
                    'align': 'LEFT'
                }
            })
                
        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
            'vex': vex
        }
    
class AngrCFGDebugInfo(Content):
        
    def __init__(self):
        super(AngrCFGDebugInfo, self).__init__('debug_info', ['text'])

    def add_line(self, data, text):
        data.append({
            'text' : {
                'align': 'LEFT',
                'content' : text
            }
        })
        
    def gen_render(self, n):
        node = n.obj

        data = []

        if node.callstack_key:
            self.add_line(data, "callstack_key: " + str([safehex(k) for k in node.callstack_key]))
        self.add_line(data, "predecessors:")
        for k in node.predecessors:
            self.add_line(data, " - " + str(k))
        self.add_line(data, "successors:")
        for k in node.successors:
            self.add_line(data, " - " + str(k))
        if hasattr(node, 'final_states'):
            self.add_line(data, "final_states: " + str(map(lambda k:hex(k.solver.eval(k.regs.ip)), node.final_states)))
#        print(dir(node))
#        self.add_line(data, "return_target: " + safehex(node.return_target))
#        self.add_line(data, "looping_times: " + str(node.looping_times))
        self.add_line(data, "size: " + str(node.size))

        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
        }



class AngrKbFunctionDetails(Content):

    def __init__(self):
        super(AngrKbFunctionDetails, self).__init__('debug_info', ['prop', 'val'])

    def add_line(self, data, prop, val):
        data.append({
            'prop' : {
                'align': 'LEFT',
                'content' : prop,
                'style':'B'
            },
            'val' : {
                'align': 'LEFT',
                'content' : val
            }
        })

    def sitespp(self, arg):
        ret = []
        for k in arg:
            if type(k).__name__ == 'BlockNode':
                ret.append(hex(k.addr))
            elif type(k).__name__ == 'HookNode':
                ret.append(hex(k.addr))
            else:
                ret.append("UNKNOWN")
        return "[" + ",".join(ret) + "]"

    def gen_render(self, n):
        fn = n.obj

        data = []
        self.add_line(data, "addr", safehex(fn.addr))

        attrs = []
        if fn.is_plt:
            attrs.append("PLT")
        if fn.is_simprocedure:
            attrs.append("SIMPROC")
        if fn.is_syscall:
            attrs.append("SYSCALL")
        
        if fn.has_return:
            attrs.append("HASRET")
        if fn.has_unresolved_calls:
            attrs.append("UNRES_CALLS")
        if fn.has_unresolved_jumps:
            attrs.append("UNRES_JUMPS")
        
        if fn.returning == True:
            attrs.append("RET")
        elif fn.returning == False:
            attrs.append("NO_RET+")
        elif fn.returning == None:
            attrs.append("NO_RET")

        if fn.bp_on_stack:
            attrs.append("BP_ON_STACK")
        if fn.retaddr_on_stack:
            attrs.append("RETADDR_ON_STACK")
            
        attrs.append("SP_DELTA_"+str(fn.sp_delta))
        
        self.add_line(data, "attributes", " ".join(attrs))    

        self.add_line(data, "num_arguments", str(fn.num_arguments))
        self.add_line(data, "arguments", str(fn.arguments))

        #self.add_line(data, "block_addrs", str(map(safehex, fn.block_addrs)))

        #xself.add_line(data, "call_convention", str(type(fn.call_convention)))
        self.add_line(data, "callout_sites", self.sitespp(fn.callout_sites))
        self.add_line(data, "jumpout_sites", self.sitespp(fn.jumpout_sites))
        self.add_line(data, "get_call_sites", str(map(hex,fn.get_call_sites())))
        self.add_line(data, "ret_sites", self.sitespp(fn.ret_sites))

        #self.add_line(data, "prepared_registers", str(fn.prepared_registers))
        #self.add_line(data, "prepared_stack_variables", str(fn.prepared_stack_variables))
        #self.add_line(data, "registers_read_afterwards", str(fn.registers_read_afterwards))
        #self.add_line(data, "get_call_return", str(fn.get_call_return(x)))
        #self.add_line(data, "get_call_target", str(fn.get_call_target(x)))
        
        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
        }


    # 'block_addrs_set', 'blocks', 'callable', 'code_constants', 'endpoints', 'get_node', 'graph', 'info', 'instruction_size', 'local_runtime_values', 'mark_nonreturning_calls_endpoints', 
    # 'nodes', 'normalize', 'operations', 'runtime_values', 'startpoint', 'string_references', 'subgraph', 'transition_graph'
