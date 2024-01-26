# Module to parse the output of prof and the dynamoRio client
import csv
import yaml

class ControlFlowGraph:
    class Module:
        def __init__(self, line='Module 0 (null)'):
            # e.g. 'Module 2 /path/to/file'
            # e.g. 'Module 5 [vdso]'
            fields = line.split(' ', 2)
            self.index = int(fields[1])
            self.path = fields[2]
            self.nodes = dict()
        def __str__(self):
            return ' '.join([
                'Module',
                str(self.index),
                self.path,
            ])

    class Node:
        def __init__(self, modules, lines):
            line = next(lines)
            # e.g. '2:2000 1 0 jz'
            fields = line.split(' ', 3)
            subfields = fields[0].split(':', 1)
            module = int(subfields[0])
            offset = int(subfields[1], 16)
            self.module = modules[module]
            self.module.nodes[offset] = self
            self.first = offset
            self.size = 0
            self.count = int(fields[1])
            self.callee_count = int(fields[2])
            self.children = []
            self.parents = dict()
            for line in lines:
                # e.g. '	+12 2'
                # e.g. '	2:2016 1'
                if line.startswith('\t+'):
                    fields = line[2:].split(' ', 1)
                    offset = int(fields[0], 16)
                    length = int(fields[1])
                    end = offset + length
                    self.size = max(self.size, end)
                else:
                    fields = line[1:].split(' ', 1)
                    subfields = fields[0].split(':',1)
                    module = int(subfields[0])
                    address = int(subfields[1], 16)
                    count = int(fields[1])
                    self.children.append((modules[module], address, count))

        def __str__(self):
            return ' '.join([
                'M' + str(self.module.index),
                hex(self.first)[2:],
                hex(self.last)[2:],
                str(self.size),
                str(self.count),
                str(self.callee_count),
            ])

    def __init__(self, input_file):
        # Parsng
        modules = dict()
        node_lines = []
        self.entries = []
        for line in input_file:
            if line.startswith("#"): continue
            if len(line) < 2: continue
            if line[-1] == '\n': line = line[:-1]
            if line[0] != '\t' and len(node_lines) > 0:
                node = ControlFlowGraph.Node(modules, iter(node_lines))
                node_lines = []
            if line.startswith('Architecture '):
                self.architecture = line[len('Architecture '):]
                continue
            elif line.startswith('Module'):
                module = ControlFlowGraph.Module(line)
                modules[module.index] = module
                continue
            elif line.startswith('Entry'):
                # e.g. 'Entry 3:1100 1'
                fields = line.split(' ', 2)
                count = int(fields[2])
                fields = fields[1].split(':', 1)
                module = int(fields[0])
                offset = int(fields[1], 16)
                entry = {'module': module, 'offset': offset, 'count': count}
                self.entries.append(entry)
                continue
            node_lines.append(line)
        if len(node_lines) > 0:
            node = ControlFlowGraph.Node(modules, iter(node_lines))

        # Post processing
        self.modules = dict()
        for module in modules.values():
            self.modules[module.path] = module
            for node in module.nodes.values():
                children = node.children
                node.children = dict()
                for cmodule, cfirst, count in children:
                    cnode = cmodule.nodes[cfirst]
                    node.children[cnode] = count
                    cnode.parents[node] = count


class InstructionsCsv:
    class Instruction:
        def __init__(self, row):
            self.module = row['path']
            self.address = int(row['inst_addr_hex'][2:],16)
            self.samples = int(row['samples'])
            self.count = int(row['execution_count'])
            self.cycles = int(row['cpu_cycle'])
            self.asm = row['disassembly']
            self.function = row['func_name']
            self.inlined = row['inlined_func']
            self.line = row['line']
        def __str__(self):
            return ','.join([
                '"' + self.module + '"',
                hex(self.address),
                str(self.samples),
                str(self.count),
                str(self.cycles),
                '"' + self.asm + '"',
                '"' + self.function + '"',
                '"' + self.inlined + '"',
                '"' + self.line + '"',
            ])
    def __init__(self, input_file):
        reader = csv.DictReader(input_file)
        self.instructions = dict()
        for row in reader:
            instr = InstructionsCsv.Instruction(row)
            if instr.module not in self.instructions:
                self.instructions[instr.module] = dict()
            self.instructions[instr.module][instr.address] = instr

class LoopsCsv:
    class Loop:
        def __init__(self, row):
            self.module = row['file']
            self.head = int(row['head_addr'][2:],16)
            self.tail = int(row['tail_addr'][2:],16)
            self.iterations = int(row['iters'])
            self.invocations = int(row['invocs'])
            self.samples = int(row['samples'])
            self.count = int(row['insts'])
            self.cycles = int(row['cycles'])
            self.coverage = float(row['cover'])
            self.function = row['loop_func']
            self.lines = row['source']
        def __str__(self):
            return ','.join([
                '"' + self.module + '"',
                hex(self.head),
                hex(self.tail),
                str(self.iterations),
                str(self.invocations),
                str(self.samples),
                str(self.count),
                str(self.cycles),
                str(self.coverage),
                '"' + self.function + '"',
                '"' + self.lines + '"',
            ])
    def __init__(self, input_file):
        reader = csv.DictReader(input_file)
        self.loops = dict()
        for row in reader:
            loop = LoopsCsv.Loop(row)
            if loop.module not in self.loops:
                self.loops[loop.module] = dict()
                self.loops[loop.module][(loop.head,loop.tail)] = loop

class ProgramStructure:
    class Module:
        def __init__(self, yaml):
            self.index = int(yaml['module'])
            self.path = str(yaml['path'])
            self.loops = []
            self.functions = dict()
        def __str__(self):
            return ' '.join([
                'Module',
                str(self.index),
                self.path,
            ])

    class Loop:
        def __init__(self, modules, function, module, yaml):
            self.module = module
            self.function = function
            module.loops.append(self)
            self.offset = yaml['loop']
            self.invocations = yaml['invocations']
            self.iterations = yaml['stats']['iterations']
            self.iter_per_invoc = yaml['stats']['iter-per-invoc']
            self.backedges = yaml['back-edges']
            self.blocks_inclusive = yaml['blocks-inclusive']
            self.blocks_exclusive = yaml['blocks-exclusive']
            self.callees = yaml['callees']
            if 'stats-inclusive' in yaml and 'cover' in yaml['stats-inclusive']:
                self.cover = yaml['stats-inclusive']['cover']
            elif 'stats-exclusive' in yaml and 'cover' in yaml['stats-exclusive']:
                self.cover = yaml['stats-exclusive']['cover']
            else: self.cover = 0
            if 'stats-inclusive' in yaml and 'cycles' in yaml['stats-inclusive']:
                self.cycles = yaml['stats-inclusive']['cycles']
            elif 'stats-exclusive' in yaml and 'cycles' in yaml['stats-exclusive']:
                self.cycles = yaml['stats-exclusive']['cycles']
            else: self.cycles = 0
            if 'stats-inclusive' in yaml and 'ipc' in yaml['stats-inclusive']:
                self.ipc = yaml['stats-inclusive']['ipc']
            elif 'stats-exclusive' in yaml and 'ipc' in yaml['stats-exclusive']:
                self.ipc = yaml['stats-exclusive']['ipc']
            else: self.ipc = 0
            if 'stats-inclusive' in yaml and 'inst-per-iter' in yaml['stats-inclusive']:
                self.inst_per_iter = yaml['stats-inclusive']['inst-per-iter']
            elif 'stats-exclusive' in yaml and 'inst-per-iter' in yaml['stats-exclusive']:
                self.inst_per_iter = yaml['stats-exclusive']['inst-per-iter']
            else: self.inst_per_iter = 0
            self.nodes = []
            if 'nodes' not in yaml: return
            for node in yaml['nodes']:
                if 'function' in node:
                    self.nodes.append(ProgramStructure.Function(modules, node))
                elif 'loop' in node:
                    self.nodes.append(ProgramStructure.Loop(modules, function, module, node))
                else:
                    raise RuntimeError("parse error")
        def resolve_callees(self, modules):
            self.callees = list(map(lambda x: modules[x['module']].functions[x['offset']], self.callees))
            for node in self.nodes: node.resolve_callees(modules)

    class Function:
        def __init__(self, modules, yaml):
            self.name = yaml['function']
            self.module = modules[int(yaml['address']['module'])]
            self.offset = yaml['address']['offset']
            self.invocations = yaml['invocations']
            self.blocks_exclusive = yaml['blocks-exclusive']
            if 'stats-inclusive' in yaml and 'cover' in yaml['stats-inclusive']:
                self.cover = yaml['stats-inclusive']['cover']
            elif 'stats-exclusive' in yaml and 'cover' in yaml['stats-exclusive']:
                self.cover = yaml['stats-inclusive']['cover']
            else: self.cover = 0
            if 'stats-inclusive' in yaml and 'cycles' in yaml['stats-inclusive']:
                self.cycles = yaml['stats-inclusive']['cycles']
            elif 'stats-exclusive' in yaml and 'cycles' in yaml['stats-exclusive']:
                self.cycles = yaml['stats-exclusive']['cycles']
            else: self.cycles = 0
            if 'stats-inclusive' in yaml and 'ipc' in yaml['stats-inclusive']:
                self.ipc = yaml['stats-inclusive']['ipc']
            elif 'stats-exclusive' in yaml and 'ipc' in yaml['stats-exclusive']:
                self.ipc = yaml['stats-exclusive']['ipc']
            else: self.ipc = 0
            if 'stats-inclusive' in yaml and 'samples' in yaml['stats-inclusive']:
                self.samples = yaml['stats-inclusive']['samples']
            elif 'stats-exclusive' in yaml and 'samples' in yaml['stats-exclusive']:
                self.samples = yaml['stats-exclusive']['samples']
            else: self.samples = 0
            self.module.functions[self.offset] = self
            self.length = yaml['address']['length']
            self.nodes = []
            self.callees = yaml['callees']
            self.callsites = dict()
            for caller in yaml['callers']:
                module = modules[caller['function']['module']]
                for site in caller['sites']:
                    self.callsites[(module, site['offset'])] = (caller['function']['offset'], site['count'])
            if 'nodes' not in yaml: return
            for node in yaml['nodes']:
                if 'function' in node:
                    self.nodes.append(ProgramStructure.Function(modules, node))
                elif 'loop' in node:
                    self.nodes.append(ProgramStructure.Loop(modules, self, self.module, node))
                else:
                    raise RuntimeError("parse error")
        def resolve_callees(self, modules):
            self.callees = list(map(lambda x: modules[x['module']].functions[x['offset']], self.callees))
            for node in self.nodes: node.resolve_callees(modules)

    def __init__(self, input_file):
        content = yaml.safe_load(input_file.read())
        modules = dict()
        for m in content['modules']:
            module = ProgramStructure.Module(m)
            modules[module.index] = module
        self.nodes = []
        for node in content['nodes']:
            if 'function' in node:
                self.nodes.append(ProgramStructure.Function(modules, node))
            else:
                raise RuntimeError("parse error")
        for node in self.nodes:
            node.resolve_callees(modules)
        self.modules = dict()
        for module in modules.values():
            self.modules[module.path] = module
