from parser import *
import pathlib
import subprocess
import sys

class Instruction:
    def __init__(self, instr, offset, block, line):
        self.raw = instr
        self.is_ret = instr.asm.startswith('ret')
        self.is_call = instr.asm.startswith('call') or instr.asm.startswith('bl')
        self.offest = offset
        self.block = block
        self.line = line
        self.inlined = None
class Block:
    def __init__(self, cfg_node, function, offset):
        self.raw = cfg_node
        self.offset = offset
        self.next = None
        self.is_tail_call = False
        self.function = function
        self.children = dict()
        self.parents = dict()
        self.instructions = []
        self.calls = dict()
        self.count = 0
        self.cycles = 0
        self.icount = 0
        self.loops = frozenset()
class Loop:
    pass
class Function:
    def __init__(self, name):
        self.name = name
        self.rawname = name
        self.shortname = name
        self.longname = name
        self.namesuffix = ''
        self.cycles = 0
        self.count = 0
        self.samples_inc = 0
        self.invocations = 0
        self.instructions = []
        self.blocks = dict()
        self.files = dict()
        self.inlineds = set()
class InlinedFunction:
    def __init__(self, name, parent):
        self.name = name
        self.rawname = name
        self.longname = name
        self.namesuffix = ''
        self.parents = set([parent])
        self.cycles = 0
        self.count = 0
        self.files = set()

def add_line(f, line):
    if line.file not in f.files:
        f.files[line.file] = (line.number,line.number)
    else:
        f.files[line.file] = (
            min(f.files[line.file][0], line.number),
            max(f.files[line.file][1], line.number)
        )

_lineid = 0
class Line:
    def __init__(self, file, number):
        global _lineid
        self.file = file
        self.number = number
        self.text = None
        self.html = None
        self.id = _lineid
        _lineid = _lineid + 1

class File:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.lines = []
        self.loaded = False
        self.syntax = False
        self.error = None
        try:
            with self.path.open() as f:
                for line in f:
                    cline = Line(self, len(self.lines)+1)
                    cline.text = line[:-1]
                    self.lines.append(cline)
            self.loaded = True
            self._p = subprocess.Popen([
                '/usr/bin/ex', '-s', '-n', '-u', 'NONE', '-i', 'NONE', '-f',
                '+syn on',
                '+let html_no_progess = 1',
                '+let html_use_css = 0',
                '+set background=light',
                '+colorscheme zellner',
                '+run! syntax/2html.vim',
                '+w! /dev/stdout',
                '+qa!',
                str(self.path),
            ], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
        except OSError as e:
            self.error = e.strerror
        except Exception as e:
            self.error = str(e)
    def process(self):
        if not self.loaded: return
        try:
            self._p.poll()
            inBody = False
            i = 0
            for b in iter(self._p.stdout.readline, ""):
                line = b.decode('utf-8')
                if line.endswith('\n'):
                    line = line[:-1]
                if line.startswith('<font face="monospace">'):
                    inBody = True
                    continue
                if not inBody: continue
                if i >= len(self.lines): break
                self.lines[i].html = line.replace("<u>","").replace("</u>","")
                i = i + 1
            self.syntax = True
        except OSError as e:
            self.error = e.strerror
        except Exception as e:
            self.error = str(e)
        finally:
            if self._p.poll() is None:
                self._p.kill()

    def get_line(self, number):
        if number < 1: return None
        while len(self.lines) <= number-1:
            self.lines.append(Line(self, len(self.lines)+1))
        return self.lines[number-1]

loop_id = 0
structure_to_node = dict()
class Node:
    def __init__(self, parent, structure_to_func, function, raw, loop=None):
        self.raw = raw
        self.parent = parent
        self.function = function
        self.is_loop = loop is not None
        if loop is None:
            self.id = 'func_' + str(raw.module.index) + "_" + str(raw.offset)
            function.node = self
            function.samples_inc = raw.samples
        else:
            global loop_id
            self.id = 'loop_' + str(loop_id)
            loop_id += 1
            self.loop = loop
        structure_to_node[raw] = self
        self.nodes = []
        self._convert_children(structure_to_func)
    def _convert_children(self, structure_to_func):
        for node in self.raw.nodes:
            if issubclass(type(node), ProgramStructure.Loop):
                self.nodes.append(Node(self, structure_to_func, self.function, node, node))
            elif issubclass(type(node), ProgramStructure.Function):
                self.nodes.append(Node(self, structure_to_func, structure_to_func[node], node))
            else:
                raise RuntimeError("Unknown node")
    def process_callees(self):
        self.callees = list(map(lambda x: structure_to_node[x] if x in
            structure_to_node else None, self.raw.callees))
        self.callsites = dict()
        if not self.is_loop:
            for k, v in self.raw.callsites.items():
                caller = k[0].functions[v[0]]
                self.callsites[(structure_to_node[caller], k[1])] = v[1]
        for node in self.nodes: node.process_callees()

class Processed:
    def __init__(self, cfg_file, inst_csv, loop_csv, structure_file):
        print("Info: parse {0}".format(cfg_file.name))
        cfg = ControlFlowGraph(cfg_file)
        print("Info: parse {0}".format(inst_csv.name))
        instrs = InstructionsCsv(inst_csv)
        print("Info: parse {0}".format(loop_csv.name))
        loops = LoopsCsv(loop_csv)
        print("Info: parse {0}".format(structure_file.name))
        structure = ProgramStructure(structure_file)

        all_functions = set()
        to_demangle = set()
        inlineds = dict()
        node_to_block = dict()
        files = dict()
        function_files = set()
        structure_to_func = dict()

        def parse_line(line):
            if line == '?:?': return None
            fields = line.rsplit(':',1)
            return (fields[0], int(fields[1]))

        self.cycles = 0
        self.count = 0
        self.is_loop = False
        self.callees = []
        print("Info: syntax highlighting source code...")
        for path, module in instrs.instructions.items():
            for addr in module.keys():
                instr = module[addr]
                pline = parse_line(instr.line)
                if pline is not None:
                    if pline[0] not in files:
                        files[pline[0]] = File(pline[0])
        for file in files.values():
            file.process()
        print("Info: processing...")
        for path, module in instrs.instructions.items():
            cfg_module = cfg.modules[path] if path in cfg.modules else None
            structure_module = structure.modules[path] if path in cfg.modules else None
            if structure_module is None:
                print("Warning: module", path, "not found", file=sys.stderr)
                continue
            for func in structure_module.functions.values():
                to_demangle.add(func.name)
                function = Function(func.name)
                structure_to_func[func] = function
                all_functions.add(function)
                block = None
                lastblock = None
                inlined = None
                for addr in range(func.offset, func.offset+func.length):
                    if addr not in module: continue
                    instr = module[addr]
                    pline = parse_line(instr.line)
                    if pline is not None:
                        line = files[pline[0]].get_line(pline[1])
                    else:
                        line = None

                    self.cycles += instr.cycles
                    self.count += instr.count
                    if block is None or cfg_module is None or instr.address in cfg_module.nodes:
                        rawblock = None
                        if cfg_module is not None and instr.address in cfg_module.nodes:
                            rawblock = cfg_module.nodes[instr.address]
                        else:
                            rawblock = lastblock
                        newblock = Block(
                            rawblock,
                            function,
                            instr.address - func.offset,
                        )
                        if block is not None: block.next = newblock
                        function.blocks[newblock.offset] = block = newblock
                        node_to_block[block.raw] = block
                        block.count = instr.count
                    function.cycles += instr.cycles
                    function.count += instr.count
                    block.cycles += instr.cycles
                    block.icount += instr.count
                    pinstr = Instruction(instr, instr.address - func.offset, block, line)
                    function.instructions.append(pinstr)
                    block.instructions.append(pinstr)
                    if line is not None and instr.inlined == instr.function:
                        add_line(function, line)
                    if instr.inlined == instr.function:
                        continue
                    if inlined is None or instr.inlined != inlined.name:
                        if instr.inlined in inlineds:
                            inlined = inlineds[instr.inlined]
                        else:
                            to_demangle.add(instr.inlined)
                            inlineds[instr.inlined] = inlined = InlinedFunction(
                                instr.inlined, function,
                            )
                        inlined.parents.add(function)
                    pinstr.inlined = inlined
                    function.inlineds.add(inlined)
                    inlined.cycles += instr.cycles
                    inlined.count += instr.count
                    if line is not None:
                        add_line(inlined, line)
                for block in function.blocks.values():
                    if block.raw is None: continue
                    for child, count in block.raw.children.items():
                        if child.module == block.raw.module \
                                and child.first - func.offset in function.blocks \
                                and not block.instructions[-1].is_call:
                            cblock = function.blocks[child.first - func.offset]
                            block.children[cblock] = count
                            cblock.parents[block] = count
                        elif block.instructions[-1].is_ret:
                            pass
                        else:
                            block.calls[child] = count
                            block.is_tail_call = not block.instructions[-1].is_call
                            if not block.is_tail_call:
                                cblock = block.next
                                if cblock is not None:
                                    block.children[cblock] = count
                                    cblock.parents[block] = count
        print("Info: demangling symbol names")
        demang_noargs = dict()
        demang_args = dict()
        inp = ''
        for s in to_demangle:
            demang_noargs[s] = s
            demang_args[s] = s
            inp += s + '\n'

        def demangle(args, res):
            try:
                with subprocess.Popen([
                            '/usr/bin/env', 'c++filt'
                        ] + args, stdout=subprocess.PIPE, stdin=subprocess.PIPE) as demang:
                    try:
                        out, err = demang.communicate(input=inp.encode(), timeout=15)
                    except subprocess.TimeoutExpired:
                        demang.kill()
                        out, err = demang.communicate()
                    out = out.decode()
                    pos = 0
                    for s in to_demangle:
                        end = out.find('\n', pos)
                        if end == -1: break
                        res[s] = out[pos:end].strip()
                        pos = end + 1
            except Exception as e:
                print("Wanrning: symbol name demangling failed: " + str(e), file=sys.stderr)
                pass # oh well
        demangle(['-p'], demang_noargs)
        demangle([], demang_args)

        def set_name(function):
            if function.rawname in demang_noargs:
                function.shortname = demang_noargs[function.rawname]
            if function.rawname in demang_args:
                function.longname = demang_args[function.rawname]
                pos = function.longname.rfind('[clone ')
                if pos != -1 and function.longname[-1] == ']':
                    function.namesuffix = function.longname[pos+7:-1]

        for function in inlineds.values(): set_name(function)
        for function in all_functions: set_name(function)

        function_names = set()
        named_functions = dict()

        def insert_function(function):
            if function.name in function_names:
                if function.name in named_functions:
                    first = named_functions[function.name]
                    if first.namesuffix != '' or function.namesuffix == '':
                        if first.name == first.shortname and first.namesuffix != '':
                            first.name = first.shortname + first.namesuffix
                            function_names.remove(function.name)
                        else:
                            first.name = first.name + " (1)"
                        del named_functions[function.name]
                        insert_function(first)
                if function.name == function.shortname and function.namesuffix != '':
                    function.name = function.shortname + function.namesuffix
                    insert_function(function)
                    return
                if function.name not in function_names:
                    insert_function(function)
                    return
                i = 1
                newname = function.name + " (" + str(i) + ")"
                while newname in named_functions:
                    i = i + 1
                    newname = function.name + " (" + str(i) + ")"
                function.name = newname
            else:
                function_names.add(function.name)
            named_functions[function.name] = function

        # Make function names unique
        for function in all_functions:
            function.name = function.shortname
            insert_function(function)

        print("Info: process functions")
        for function in named_functions.values():
            for block in function.blocks.values():
                new_calls = dict()
                for target, count in block.calls.items():
                    target_block = node_to_block[target]
                    new_calls[target_block] = count
                    target_block.function.invocations += count
                block.calls = new_calls

        self.nodes = []
        for node in structure.nodes:
            self.nodes.append(Node(self, structure_to_func, structure_to_func[node], node))
        for node in self.nodes: node.process_callees()

        self.functions = named_functions
        self.inlined = inlineds
