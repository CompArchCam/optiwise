import colorsys
import graphviz
import html
import math
import urllib.parse

def _make_page(title, body):
    return '\n'.join([
        '<!DOCTYPE html>',
        '<html>',
        ' <head>',
        '  <meta charset="utf-8">',
        '  <title>' + html.escape(title, quote=False) + '</title>',
        '  <style>',
        '.function-name { font-family: monospace; }',
        '*[onclick] { cursor: pointer; }',
        'body { background: #fff; }',
        'body > h1 { display: inline; }',
        'body > h3 { display: inline; }',
        '.structure-svg { max-width: 100%; overflow-x: scroll; }',
        '@media (width <= 100em) {',
            '.main-area {  position: absolute; top: 18em; bottom: 0; left: 0; right: 0; overflow: scroll; }',
            '.asm-svg { position: absolute; top: 0; bottom: 0; left: 0; right: 0; overflow: scroll; }',
            '.asm-table { position: absolute; top: 0; bottom: 0; left: 0; right: 0; overflow: scroll; }',
            '.code-listing { position: absolute; top: 0; bottom: 0; left: 0; right: 0; overflow: scroll; }',
            '.show-if-medium { display: none; }',
            '.tab-small { display: none; }',
            '.tab-small[data-selected] { display: initial; }',
        '}',
        '@media (100em < width <= 150em) {',
            '.main-area { position: absolute; top: 18em; bottom: 0; left: 0; right: 0; overflow: scroll; }',
            '.asm-svg { position: absolute; top: 0; bottom: 0; left: 0; width: 50%; overflow: scroll; }',
            '.asm-table { position: absolute; top: 0; bottom: 0; left: 50%; right: 0; overflow: scroll; border-left: black solid; border-right: black solid; box-sizing: border-box; }',
            '.code-listing { position: absolute; top: 0; bottom: 0; left: 0; right: 0; overflow: scroll; }',
            '.show-if-small { display: none; }',
            '.tab-medium { display: none; }',
            '.tab-medium[data-selected] { display: initial; }',
            '.asm-svg svg { margin: 50%; }',
            '.asm-table table { margin: 50% 1em; }',
        '}',
        '@media (width > 150em) {',
            '.asm-svg { position: absolute; top: 15em; bottom: 0; left: 0; width: 30%; overflow: scroll; }',
            '.asm-table { position: absolute; top: 15em; bottom: 0; left: 30%; right: 40%; overflow: scroll; border-left: black solid; border-right: black solid; box-sizing: border-box; }',
            '.code-listing { position: absolute; top: 15em; bottom: 0; left: 60%; right: 0; overflow: scroll; }',
            '.show-if-small { display: none; }',
            '.show-if-medium { display: none; }',
            '.asm-svg svg { margin: 50%; }',
            '.asm-table table { margin: 50% 1em; }',
            '.code-listing table { margin: 50% 1em; }',
        '}',
        '.tab-control { position: absolute; top: 15em; left: 0; right: 0; }',
        '.button{',
            'display: block;',
            'float: left;',
            'padding:5px 15px;',
            'text-align:center;',
            'margin:5px;',
            'border-radius:5px;',
            '-moz-border-radius:5px;',
            '-webkit-border-radius:5px;',
            'background-color:#428bca;',
            'border-color:#357ebd;',
            'border:1px solid;',
            'color:#FFF;',
            'text-decoration:none;',
        '}',
        'button:hover{',
            'color:#FFF;',
            'background-color:#357ebd;',
            'border-color:#428bca;',
        '}',
        '.caller-list { position: absolute; top: 5em; height: 10em; left: 0; width: 50%; overflow: scroll; }',
        '.loop-list { position: absolute; top: 5em; height: 10em; right: 0; width: 50%; overflow: scroll; }',

        '.caller-list table { white-space: nowrap; border-collapse: collapse; }',
        '.caller-list thead tr { position: sticky; top: 0.0em; border: white thick solid; background: white; }',
        '.caller-list td { text-align: right; }',
        '.caller-list th { text-align: right; padding-left: 1em; vertical-algin: bottom; }',
        '.caller-list td:nth-child(1) { font-family: monospace; }',
        '.caller-list td:nth-child(2) { font-family: monospace; }',

        '.loop-list table { white-space: nowrap; border-collapse: collapse; }',
        '.loop-list thead tr { position: sticky; top: 0.0em; border: white thick solid; background: white; }',
        '.loop-list td { text-align: right; }',
        '.loop-list th { text-align: right; padding-left: 1em; vertical-algin: bottom; }',
        '.loop-list td:nth-child(1) { text-align: left; font-family: monospace; }',
        '.loop-list th:nth-child(1) { text-align: left; }',

        '.asm-svg h3 { position: sticky; left: 0.0em; top: 0.0em; border: white thick solid; background: white; }',

        '.asm-table table { white-space: nowrap; border-collapse: collapse; }',
        '.asm-table thead tr { position: sticky; top: 0.0em; border: white thick solid; background: white; }',
        '.asm-table tr { text-align: right; }',
        '.asm-table td:nth-child(1) { font-family: monospace; }',
        '.asm-table td:nth-child(2) { font-family: monospace; text-align: left; }',
        '.asm-table td:nth-child(7) { text-align: left; }',
        '.asm-table th:nth-child(2) { text-align: left; }',
        '.asm-table th:nth-child(7) { text-align: left; }',
        '.asm-table .block-rest td:nth-child(1) { color: #999999; }',
        '.asm-table .block-rest td:nth-child(6) { color: #999999; }',
        '.asm-table .line-rest { color: #999999; }',

        '.code-listing table { border-collapse: collapse; }',
        '.code-listing h3 { position: sticky; left: 0.0em; top: 0.0em; border: white thick solid; background: white; white-space: nowrap; overflow-y: hidden; }',
        '.code-listing td { text-align: right; }',
        '.code-listing td:nth-child(4) { text-align: left; }',
        '.code-listing pre { margin: 0 }',
        '.code-listing .line-irrelevant { background: #eee; }',
        '.code-listing .line-irrelevant td:nth-child(1) * { display: none; }',
        '.code-listing .line-irrelevant td:nth-child(2) * { display: none; }',
        '  </style>',
        '  <script>',
        'function smooth_scroll(container, node) {',
        '  const crect = container.getBoundingClientRect();',
        '  const brect = node.getBoundingClientRect();',
        '  container.scrollBy({',
        '    left: (brect.left - crect.left) + (brect.width - crect.width) / 2,',
        '    top: (brect.top - crect.top) + (brect.height - crect.height) / 2,',
        '    behavior: "smooth",',
        '  });',
        '}',
        'function is_hidden(el) {',
        '  return (el.offsetParent === null)',
        '}',
        'delay_select_block = null;',
        'function select_block(id) {',
        '  const containers = document.getElementsByClassName("asm-svg")',
        '  if (containers.length != 1) return;',
        '  const container = containers[0];',
        '  const nodes = container.getElementsByClassName("cfg-n" + id.toString())',
        '  if (nodes.length != 1) return;',
        '  delay_select_block = null;',
        '  if (is_hidden(container)) delay_select_block = id;',
        '  else smooth_scroll(container, nodes[0]);',
        '}',
        'delay_select_asm = null;',
        'function select_asm(id) {',
        '  const containers = document.getElementsByClassName("asm-table")',
        '  if (containers.length != 1) return;',
        '  const container = containers[0];',
        '  const nodes = container.querySelectorAll("a[name=\\"" + id.toString(16) + "\\"]")',
        '  if (nodes.length != 1) return;',
        '  delay_select_asm = null;',
        '  if (is_hidden(container)) delay_select_asm = id;',
        '  else smooth_scroll(container, nodes[0]);',
        '}',
        'delay_select_line = null;',
        'function select_line(id) {',
        '  const containers = document.getElementsByClassName("code-listing")',
        '  if (containers.length != 1) return;',
        '  const container = containers[0];',
        '  const nodes = container.querySelectorAll(".line-" + id.toString() + "")',
        '  if (nodes.length != 1) return;',
        '  delay_select_line = null;',
        '  if (is_hidden(container)) delay_select_line = id;',
        '  else smooth_scroll(container, nodes[0]);',
        '}',
        'function select_tab(size, id) {',
        '  const tabs = document.getElementsByClassName("tab-" + size);',
        '  for (i = 0; i < tabs.length; i++) {',
        '    tabs[i].removeAttribute("data-selected");',
        '    if (tabs[i].getAttribute("data-tab-id") != id) continue;',
        '    tabs[i].setAttribute("data-selected", "");',
        '  }',
        '  setTimeout(() => {',
        '    if (delay_select_block) select_block(delay_select_block);',
        '    if (delay_select_asm) select_asm(delay_select_asm);',
        '    if (delay_select_line) select_line(delay_select_line);',
        '  }, 0);'
        '}',
        '  </script>',
        ' </head>',
        ' <body>',
        body,
        ' </body>',
        '</html>',
    ])

def hsv_to_html(h, s, v):
    c = colorsys.hsv_to_rgb(h, s, v)
    return '#{0:02x}{1:02x}{2:02x}'.format(
        int(c[0] * 0xff),
        int(c[1] * 0xff),
        int(c[2] * 0xff),
    )

def _cpi_color(cycles, count):
    if count == 0: return 'black'
    cpi = cycles / count
    return hsv_to_html(0.1, min(1, cpi * 2 / 10), min(1, cpi / 10))
def _cycles_color(cycles, function_cycles):
    if function_cycles == 0: return 'black'
    cycles = cycles / function_cycles
    return hsv_to_html(0.1, min(1, cycles * 2 * 10), min(1, cycles * 10))
def _cover_color(cover):
    return hsv_to_html(0.1, cover / 3, 1)


# https://stackoverflow.com/a/25808207
def safePath(url):
    url = url.replace('::', '.')
    return ''.join(map(lambda ch:
        chr(ch) if ch in safePath.chars
        else '[' if ch == ord('<')
        else ']' if ch == ord('>')
        else '.' if ch == ord(':')
        else '.' if ch == ord(',')
        else '%%%02x' % ch, url.encode('utf-8')
    ))[:128]
safePath.chars = frozenset(map(lambda x: ord(x), '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+-_ .(){}[]^&;@!'))

class Renderer:
    def __init__(self, processed):
        self.processed = processed

    def render_functions(self):
        rows = sorted(self.processed.functions.values(), key=lambda x: -x.node.raw.cover)
        rows = map(lambda x: ''.join([
            '<tr>',
            '<td>', '<a',
            '' if self.function_filename(x) is None else ' href="' + urllib.parse.quote(self.function_filename(x)) + '"',
            '>', x.name, '</a></td>',
            '<td>', '{0:.1%}'.format(x.node.raw.cover), '</td>',
            '<td>', '{0:.1%}'.format(x.cycles / self.processed.cycles), '</td>',
            '<td>', str(x.invocations), '</td>',
            '<td>', '-' if x.node.raw.cover == 0 else '{0:.2f}'.format(x.node.raw.ipc), '</td>',
            '<td>', '-' if x.cycles == 0 else '{0:.2f}'.format(x.count / x.cycles), '</td>',
            '</tr>'
        ]), rows)
        digraph = graphviz.Digraph('structure',
            graph_attr={'ranksep':'0.2', 'splines': 'ortho', 'tooltip':'Dynamic program structure'},
            node_attr={'fontsize':'9.0', 'width':'0', 'height':'0'},
            edge_attr={'fontsize':'9.0', 'arrowsize':'0.5'},
        )
        self._render_structure_svg(digraph, None, self.processed)
        svg = digraph.pipe('svg').decode('utf-8')
        svg = svg[svg.find('<svg'):]
        return _make_page('Functions list', '\n'.join([
            '<h1>Structure</h1>',
            '<p>Dynamic structure of the program showing all functions and',
            'loops encountered during execution with more than 1% execution time. Rectangles represent',
            'functions, ellipses represent loops. Arrows represent calls to ',
            'functions, or invocations of loops.</p>',
            '<div class="structure-svg">', svg, '</div>',
            '<h1>All functions</h1>',
            '<table>',
            ' <thead><tr><th>Name</th><th>Cycles</th><th>Self cycles</th><th>Invocations</th><th>IPC</th><th>Self IPC</th></tr></thead>',
            ' <tbody>', '\n'.join(rows), '</tbody>'
            '</table>',
        ]))

    def _render_structure_svg(self, digraph, parent, structure, dotty=False, func=None):
        def is_trivial(node):
            return (len(node.nodes) > 0
                and (len(node.nodes) <= 1 or node.nodes[1].raw.cover < 0.005)
                and node.nodes[0].raw.cover >= 0.995
                and not node.nodes[0].is_loop
            )
        func=func if structure.is_loop else structure
        if parent is None:
            if is_trivial(structure) and is_trivial(structure.nodes[0]):
                self._render_structure_svg(digraph, None, structure.nodes[0], func=func)
                return

        with digraph.subgraph() as s:
            s.attr(rank='same')
            first = True
            for node in structure.nodes:
                if node.raw.cover < 0.01: continue
                node_name = node.id
                if node.is_loop:
                    filename = self.function_filename(func.function)
                    url = None if filename is None else '' + urllib.parse.quote(filename) + '#' + hex(node.raw.offset)[2:]
                    s.node(
                        node_name,
                        label=''.join([
                            '<',
                            'Loop {0:.1f}&times;'.format(node.raw.iter_per_invoc),
                            '<BR /><FONT POINT-SIZE="8.0" FACE="sans">',
                            str(node.raw.invocations),
                            '</FONT><BR /><FONT POINT-SIZE="8.0" FACE="sans">',
                            '{0:.0%} (IPC {1:.2f})'.format(node.raw.cover, node.raw.ipc),
                            '</FONT>>',
                        ]),
                        fillcolor=_cover_color(node.raw.cover),
                        tooltip=('A loop in the function "{0}" that is executed {2} ' +
                        'times with {3} iterations per execution on average. {1:.0%} of '+
                        'execution time is spent in this loop and its ' +
                        'children.').format(func.function.name, node.raw.cover,
                            node.raw.invocations, node.raw.iter_per_invoc),
                        style='filled',
                        URL=url,
                    )
                else:
                    filename = self.function_filename(node.function)
                    url = None if filename is None else '' + urllib.parse.quote(filename)
                    s.node(
                        node_name,
                        label=''.join([
                            '<',
                            '<FONT FACE="monospace">',
                            html.escape(node.function.name),
                            '</FONT><BR /><FONT POINT-SIZE="8.0" FACE="sans">',
                            str(node.raw.invocations),
                            '</FONT><BR /><FONT POINT-SIZE="8.0" FACE="sans">',
                            '{0:.0%} (IPC {1:.2f})'.format(node.raw.cover, node.raw.ipc),
                            '</FONT>>',
                        ]),
                        fillcolor=_cover_color(node.raw.cover),
                        shape='box',
                        tooltip=('A function named "{0}" called {2} ' +
                        'times. {1:.0%} of '+
                        'execution time is spent in this function and its ' +
                        'callees.').format(node.function.name, node.raw.cover,
                            node.raw.invocations),
                        style='filled',
                        URL=url,
                    )
                if parent is not None:
                    hide = not node.is_loop and node not in node.parent.callees
                    digraph.edge(parent, node_name, **{
                        'constraint':'true' if first else 'false',
                        'style':'invis' if hide else '',
                        'tooltip':'Loop entry' if node.is_loop else 'Function call',
                    })
                for callee in node.callees:
                    if callee is None: continue
                    if callee.raw.cover < 0.01: continue
                    if callee in node.nodes: continue
                    flat_nodes = set()
                    def flatten(node):
                        flat_nodes.add(node)
                        for n in node.nodes:
                            if n.is_loop and n.raw.cover < 0.01:
                                flat_nodes.add(n)
                                flatten(n)
                    flatten(node)
                    found = False
                    for site in callee.raw.callsites.keys():
                        for n in flat_nodes:
                            if site[0] == callee.raw.module and site[1] in n.raw.blocks_exclusive:
                                found = True
                                break
                        if found: break
                    if not found: continue
                    digraph.edge(node_name, callee.id, **{
                        'constraint':'false',
                        'tooltip':'Function call',
                    })
                first = False

        for node in structure.nodes:
            if node.raw.cover < 0.01: continue
            node_name = node.id
            self._render_structure_svg(digraph, node_name, node, func=func)

    def _render_asm_svg(self, function, block_colors):
        loop_colors = dict()
        for block in function.blocks.values():
            hue = len(block_colors) * 0.4314159
            loop_colors[block.instructions[0].raw.address] =  hsv_to_html(hue, 0.1, 1.0)
            block_colors[block] = hsv_to_html(hue, 0.2, 1.0)
        def _render_asm_svg_recursive(self, cfg, root, function, node, block_colors):
            for block in function.blocks.values():
                if not block.instructions[0].raw.address in node.raw.blocks_exclusive: continue
                lines = dict()
                for i in block.instructions:
                    if i.line is None: continue
                    if i.line not in lines: lines[i.line] = 0
                    lines[i.line] += max(1, i.raw.cycles)
                line = None
                for k, v in lines.items():
                    if line is None or lines[k] > lines[line]:
                        line = k
                node_name = 'n' + str(block.offset)
                cfg.node(
                    node_name,
                    label=''.join([
                        '<',
                        '<FONT FACE="monospace">',
                        hex(block.instructions[0].raw.address)[2:],
                        '</FONT><BR /><FONT POINT-SIZE="8.0" FACE="sans">',
                        str(block.count),
                        '</FONT><BR /><FONT POINT-SIZE="8.0" FACE="sans">',
                        '-' if function.cycles == 0 else
                        '0%' if block.cycles == 0 else
                        '{0:.0%} (IPC {1:.2f})'.format(block.cycles / max(1, function.cycles), block.icount / max(1, block.cycles)),
                        '</FONT>>',
                    ]),
                    fillcolor=block_colors[block],
                    shape='box',
                    style='filled',
                    height=str(math.log(len(block.instructions)) / 3),
                    URL='javascript:' + ('' if line is None else 'select_line({0})%3b'.format(line.id)) +  'select_asm({0})%3bselect_tab(%22small%22,%22asm%22)%3b'.format(block.instructions[0].raw.address),
                    tooltip=('Block at hexadecimal offset {1} containing {0} '
                        'instructions. The block executes {2} times and takes '
                        '{3:.0%} of the function\'s own execution time.').format(
                            len(block.instructions),
                            hex(block.instructions[0].raw.address)[2:],
                            block.count,
                            block.cycles / max(1, function.cycles),
                    ),
                    **{'class':'cfg-'+node_name},
                )
                if block.offset == 0:
                    root.edge('Entry', node_name, **{'tooltip':'Function entry','color':'#000066'})
                if len(block.calls) > 0:
                    call_node_name = node_name + '_callees'
                    tooltip = 'Function call' + ('s' if len(block.calls) > 1 else '') + ' from preceeding block'
                    label = '<<TABLE TITLE="' + tooltip + '" BORDER="0">'
                    for child, count in block.calls.items():
                        filename = self.function_filename(child.function)
                        href = '' if filename is None else ' HREF="' + urllib.parse.quote(filename) + '"'
                        label += ('<TR><TD BORDER="0"' + href +
                            '><FONT FACE="monospace">' +
                            html.escape(child.function.name) + "</FONT>")
                        if len(block.calls) > 1:
                            label += '</TD><TD>{0:.0%} ({1})'.format(count / max(1, float(block.count)),count)
                        label += '</TD></TR>'
                    label += '</TABLE>>'
                    cfg.node(
                        call_node_name,
                        label=label,
                        style='filled',
                        fillcolor='white',
                        shape='box',
                        tooltip=tooltip,
                    )
                    root.edge(node_name, call_node_name, **{'tooltip':'Function call'})
                    if block.is_tail_call:
                        root.edge(call_node_name, 'Return', **{'tooltip':'Function return via tail call','color':'#660000'})
                    else:
                        for n in block.children.keys():
                            root.edge(call_node_name, 'n' + str(n.offset))
                elif block.instructions[-1].is_ret:
                    root.edge(node_name, 'Return', **{'tooltip':'Function returns','color':'#660000'})
                else:
                    for child, count in block.children.items():
                        is_backedge = node.is_loop and node.raw.offset == child.instructions[0].raw.address
                        if len(block.children) > 1:
                            percent = count / max(1, float(block.count))
                            label = '{0:.0%} ({1})'.format(percent,count)
                            tooltip = 'Block {0} was follwed by block {1} {2:.0%} of the time.'.format(
                                        hex(block.instructions[0].raw.address)[2:],
                                        hex(child.instructions[0].raw.address)[2:],
                                        percent
                                    )
                        else:
                            label = ''
                            tooltip = 'Block {0} was always follwed by block {1}.'.format(
                                        hex(block.instructions[0].raw.address)[2:],
                                        hex(child.instructions[0].raw.address)[2:],
                                    )
                        if is_backedge:
                            tooltip += ' This is a backedge of the loop.'
                        if is_backedge:
                            root.edge('n' + str(child.offset), node_name,
                                    label=label, **{'penwidth':'2.0','dir':'back','tooltip':tooltip})
                        else:
                            root.edge(node_name, 'n' + str(child.offset),
                                    label=label, **{'tooltip':tooltip})
            for child in node.nodes:
                if not child.is_loop: continue
                cover = child.raw.cycles / max(1,child.raw.cycles,function.node.raw.cycles)
                ipc = child.raw.ipc
                with cfg.subgraph(name='cluster_' + child.id, body=[
                        (
                            'tooltip="A loop at offset {4} that executes {2} times with {0:.1f} '
                            'iterations per execution on average. {1:.0%} of '
                            'execution time of this function is spent in this '
                            'loop and its callees."'
                            'label=<'
                            'Loop {0:.1f}&times;'
                            '<BR /><FONT POINT-SIZE="8.0" FACE="sans">'
                            '{2}'
                            '</FONT><BR /><FONT POINT-SIZE="8.0" FACE="sans">'
                            '{1:.0%} (IPC {3:.2f})'
                            '</FONT>>'
                        ).format(
                            child.raw.iter_per_invoc,
                            cover,
                            child.raw.invocations,
                            ipc,
                            hex(child.raw.offset)[2:]
                        ),
                        'fillcolor="' + loop_colors[child.raw.offset] + '"',
                        'shape=rounded',
                        'style=filled']) as s:
                    _render_asm_svg_recursive(self, s, root, function, child, block_colors)
        cfg = graphviz.Digraph('cfg',
            graph_attr={
                'ranksep':'0.0',
                'tooltip':'Graph showing the basic blocks in the function and how'
                ' control flow passes between them. Loops and function calls are '
                ' highlighted as well as the function entry and exit.',
            },
            node_attr={'fontsize':'9.0', 'width':'0', 'height':'0'},
            edge_attr={'fontsize':'9.0', 'arrowsize':'0.5'},
        )
        cfg.node('Entry', tooltip='Function entry point')
        cfg.node('Return', tooltip='Function exit point')
        with cfg.subgraph() as s:
            _render_asm_svg_recursive(self, s, cfg, function, function.node, block_colors)
        result = cfg.pipe('svg').decode('utf-8')
        result = result[result.find('<svg'):]
        return result
    def _render_asm_table(self, function, block_colors):
        rows = function.instructions
        first = rows[0].raw.address
        def cpi(instr):
            if instr.raw.count == 0: return '-'
            return '{0:.2f}'.format(instr.raw.cycles / instr.raw.count)
        def cpi_color(instr):
            return _cpi_color(instr.raw.cycles, instr.raw.count)
        def cycles(instr):
            if function.cycles == 0: return '-'
            return '{0:.1%}'.format(instr.raw.cycles / function.cycles)
        def cycles_color(instr):
            return _cycles_color(instr.raw.cycles, function.cycles)
        def line_class(instr, prev_instr):
            first = (
                prev_instr is None
                or prev_instr.block is not instr.block
                or prev_instr.line is not instr.line
            )
            return 'line-first' if first else 'line-rest'
        def print_asm(asm):
            if asm.endswith('>') and '+0x' in asm[asm.rfind('<')+1:]:
                asm = asm[:asm.rfind('<')]
            return html.escape(asm, quote=False)
        rows = map(lambda x: ''.join([
            '<tr',
            ' title="Offset in hexadecimal into program/library"',
            ' class="', 'block-first' if x[0].block.instructions[0] is x[0] else 'block-rest', '"',
            ' onclick="',
            '  select_block(', str(x[0].block.offset), ');',
            '  select_tab(\'small\', \'cfg\');',
            '' if x[0].line is None else '  select_line(' + str(x[0].line.id) + ');',
            ' "',
            '>',
            '<td',
            ' style="background: ', block_colors[x[0].block] , ';"',
            '>',
                '<a name="' + hex(x[0].raw.address)[2:] + '">',
                    hex(x[0].raw.address)[2:],
                '</a>',
            '</td>',
            '<td title="Assembly code">', print_asm(x[0].raw.asm), '</td>',
            '<td title="Average cycles per instruction, i.e. average execution time" style="color: ', cpi_color(x[0]), '">', cpi(x[0]), '</td>',
            '<td title="Percentage of function\'s own exeuction time sepnt on this instruction" style="color: ', cycles_color(x[0]), '">', cycles(x[0]), '</td>',
            '<td title="Total samples on this instruction. Small values (e.g. less than 10) should not be considered statistically significant">', str(x[0].raw.samples), '</td>',
            '<td title="Number of times this instruction executed">', str(x[0].raw.count), '</td>',
            '<td',
            ' title="Source code line corresponding to this instruction according to the compiler"',
            ' class="', line_class(x[0], x[1]), '"',
            ' onclick="',
            '  select_block(', str(x[0].block.offset), ');',
            '  select_tab(\'small\', \'listing\');',
            '  select_tab(\'medium\', \'listing\');',
            '' if x[0].line is None else '  select_line(' + str(x[0].line.id) + ');',
            '  event.stopPropagation();',
            ' "',
            '>',
                '' if x[0].line is None else x[0].line.file.path.name + ' ' + str(x[0].line.number),
                '' if x[0].inlined is None else ' ({0})'.format(x[0].inlined.name),
            '</td>',
            '</tr>'
        ]), zip(rows, [None] + rows[0:-1]))
        return '\n'.join([
            '<table>',
            ' <thead><tr>',
            '   <th title="Offset in hexadecimal into program/library">Offset</th>',
            '   <th title="Assembly code">ASM</th>',
            '   <th title="Average cycles per instruction, i.e. average execution time">CPI</th>',
            '   <th title="Percentage of function\'s own exeuction time sepnt on this instruction">Cycles</th>',
            '   <th title="Total samples on this instruction. Small values (e.g. less than 10) should not be considered statistically significant">Samples</th>',
            '   <th title="Number of times this instruction executed">Exeuctions</th>',
            '   <th title="Source code line corresponding to this instruction according to the compiler">Line</th>',
            ' </tr></thead>',
            ' <tbody>', '\n'.join(rows), '</tbody>',
            '</table>',
        ])
    def _render_caller_table(self, function):
        rows = []
        for caller, count in function.node.callsites.items():
            func = caller[0].function
            filename = self.function_filename(func)
            href = '' if filename is None else ' href="' + urllib.parse.quote(filename) + '#' + hex(caller[1])[2:] + '"'
            rows.append(''.join([
                '<tr>',
                '<td title="Name of calling function">',
                '<a', href, '>', func.name, '</a>',
                '</td>',
                '<td title="Offset in hexadecimal of the block that calls this function">', hex(caller[1])[2:], '</td>',
                '<td title="Number of times the call occurs">', str(count), '</td>',
                '</tr>',
            ]))
        if len(rows) == 0:
            return 'This function has no dynamic callers'
        return '\n'.join([
            '<table>',
            ' <thead><tr>',
            '   <th title="Name of calling function">Caller</th>',
            '   <th title="Offset in hexadecimal of the block that calls this function">Block</th>',
            '   <th title="Number of times the call occurs">Calls</th>',
            ' </tr></thead>',
            ' <tbody>', '\n'.join(rows), '</tbody>',
            '</table>',
        ])

    def _render_loop_table(self, function, block_colors):
        def recursive_rows(loop, depth = 0):
            block = function.blocks[loop.raw.offset - function.node.raw.offset]
            rows = [''.join([
                '<tr',
                ' onclick="',
                '  select_block(', str(block.offset), ');',
                '  select_asm(', str(loop.raw.offset), ');',
                ' "',
                '>',
                '<td'
                ' title="Offset in hexadecimal of the start of the loop"'
                ' style="',
                ' padding-left: ', str(depth), 'em;',
                ' background: ', block_colors[block], ';',
                '"',
                '>', hex(loop.raw.offset)[2:], '</td>',
                '<td title="Number of times loop is entered">', str(loop.raw.invocations), '</td>',
                '<td title="Average number of times loop is entered per entry to this function">{0:.1f}</td>'.format(loop.raw.invocations / max(1, function.invocations)),
                '<td title="Total number of iterations of this loop">', str(loop.raw.iterations), '</td>',
                '<td title="Average number of iterations of this loop per loop entry">{0:.1f}</td>'.format(loop.raw.iter_per_invoc),
                '<td title="Average instructions executed per cycle during this loop">{0:.2f}</td>'.format(loop.raw.ipc),
                '<td title="Average instructions executed per iteration during this loop">{0:.1f}</td>'.format(loop.raw.inst_per_iter),
                '</tr>',
            ])]
            for node in loop.nodes:
                if node.is_loop:
                    rows.extend(recursive_rows(node, depth + 1))
            return rows
        rows = []
        for node in function.node.nodes:
            if node.is_loop:
                rows.extend(recursive_rows(node))
        if len(rows) == 0:
            return 'This function has no dynamic loops'
        return '\n'.join([
            '<table>',
            ' <thead><tr>',
            '   <th title="Offset in hexadecimal of the start of the loop">Loop</th>',
            '   <th title="Number of times loop is entered">Invocations</th>',
            '   <th title="Average number of times loop is entered per entry to this function">Invocations<br /> per call</th>',
            '   <th title="Total number of iterations of this loop">Iterations</th>',
            '   <th title="Average number of iterations of this loop per loop entry">Iterations per<br />invocation</th>',
            '   <th title="Average instructions executed per cycle during this loop">IPC</th>',
            '   <th title="Average instructions executed per iteration during this loop">Instructions per<br />iteration</th>',
            ' </tr></thead>',
            ' <tbody>', '\n'.join(rows), '</tbody>',
            '</table>',
        ])
    def _render_code_listing(self, function, block_colors):
        if len(function.files) == 0: return ''
        files = dict()
        for f, l in function.files.items():
            files[f] = [(l[0], l[1])]
            for inlined in function.inlineds:
                for file, lrange in inlined.files.items():
                    if file in files:
                        files[file].append((lrange[0], lrange[1]))
                    else:
                        files[file] = [(lrange[0], lrange[1])]
        def line_class(line, ranges):
            for minline, maxline in ranges:
                if line.number >= minline and line.number <= maxline:
                    return 'line-relevant'
            return 'line-irrelevant'
        def line_block(lines):
            blocks = dict()
            for instruction in function.instructions:
                if instruction.line is not line: continue
                if instruction.block not in blocks:
                    blocks[instruction.block] = 0
                blocks[instruction.block] += instruction.raw.cycles + 1
            block = None
            m = 0
            for b, c in blocks.items():
                if c <= m: continue
                m = c
                block = b
            return block
        line_blocks = dict()
        for file in files.keys():
            last_block = None
            empty_lines = []
            for line in file.lines:
                b = line_block(line)
                line_blocks[line] = b
                if line.text is not None and line.text.strip() == '':
                    empty_lines.append(line)
                else:
                    if last_block is not None and last_block == b:
                        for l in empty_lines:
                            line_blocks[l] = b
                    empty_lines = []
                    last_block = None
                if b is not None: last_block = b
        def line_onclick(line):
            m = None
            cycles = -1
            for instruction in function.instructions:
                if instruction.line is not line: continue
                if instruction.raw.cycles < cycles: continue
                cycles = instruction.raw.cycles
                m = instruction
            block = line_blocks[line]
            if m is None and block is None: return ''
            if m is None:
                m = block.instructions[0]
            if block is None:
                block = m.block
            return 'onclick=\'select_block({0}); select_asm({1});select_tab("small", "cfg");select_tab("medium", "cfg-asm");\''.format(
                block.offset,
                m.raw.address,
            )
        def line_cpi(line):
            cycles = 0
            count = 0
            static = 0
            for instruction in function.instructions:
                if instruction.line is not line: continue
                static += 1
                cycles += instruction.raw.cycles
                count += instruction.raw.count
            cpi = '-' if count == 0 else '{0:.2f}'.format(cycles / count)
            return \
                '<span style="color: {0}" title="Average CPI (cycles per instruction) of the {1} instruction(s) associated with this line.">{2}</span>'.format(
                    _cpi_color(cycles, count),
                    static,
                    cpi,
                );
        def line_cover(line):
            if function.cycles == 0: return '-'
            cycles = 0
            for instruction in function.instructions:
                if instruction.line is not line: continue
                cycles += instruction.raw.cycles
            if cycles == 0: return '-'
            return '<span style="color: {0}">{1:.1%}</span>'.format(
                _cycles_color(cycles, function.cycles),
                cycles / function.cycles,
            )
        def line_block_color(lines):
            prev = lines[0]
            line = lines[1]
            succ = lines[2]
            prev = None if prev is None else line_blocks[prev]
            line = line_blocks[line]
            succ = None if succ is None else line_blocks[succ]
            if line is None: return ''
            prev_same = prev is not None and block_colors[line] == block_colors[prev]
            succ_same = succ is not None and block_colors[line] == block_colors[succ]
            return (
                'background: ' + block_colors[line] + '; border: 1px black solid;' +
                ('' if not prev_same else 'border-top: initial;') +
                ('' if not succ_same else 'border-bottom: initial;') +
                ''
            )
        def line_text(line):
            if line.html is not None: return '<pre>' + line.html + '</pre>'
            if line.text is not None: return '<pre>' + html.escape(line.text, quote=False) + '</pre>'
            if line.file.error is not None: return html.escape(line.file.error, quote=False)
            return '(null)'

        listings = map(lambda x: '\n'.join([
            '<h3 title="' + html.escape(str(x[0].path), True) + '">', html.escape(str(x[0].path.name)), '</h3>\n',
            '<table>',
            ' <tbody>',
            '\n'.join(map(lambda line: ''.join([
                '<tr',
                ' class="', line_class(line[1], x[1]), '"',
                ' ', line_onclick(line[1]),
                '>',
                '<td title="Average cycles per instruction (execution time) for instructions associated with this line.">',
                line_cpi(line[1]),
                '</td>',
                '<td title="Percentage of this function&apos;s execution time spent on instructions associated with this line.">',
                line_cover(line[1]),
                '</td>',
                '<td',
                '' if line_blocks[line[1]] is None else
                    ' title="Most instructions associated with this line are in basic block {0}."'.format(
                        hex(line_blocks[line[1]].instructions[0].raw.address)[2:]
                    ),
                ' style="', line_block_color(line), '"',
                ' class="line-', str(line[1].id), '">',
                str(line[1].number),
                '</td>',
                '<td>', line_text(line[1]), '</td>',
                '</tr>',
            ]), zip([None] + x[0].lines[0:-1], x[0].lines, x[0].lines[1:] + [None]))),
            '</tbody>',
            '</table>',
        ]), files.items())
        return '\n'.join(listings)


    def render_function(self, function):
        block_colors = dict()
        dot = self._render_asm_svg(function, block_colors)
        caller_table = self._render_caller_table(function)
        loop_table = self._render_loop_table(function, block_colors)
        table = self._render_asm_table(function, block_colors)
        listing = self._render_code_listing(function, block_colors)
        cycles = 0
        i = function.instructions[0]

        for instruction in function.instructions:
            if instruction.raw.cycles > cycles:
                cycles = instruction.raw.cycles
                i = instruction
        name = html.escape(function.name, quote=False)
        return _make_page(name + ' - performance analysis', '\n'.join([
            '<a class="button" href="index.html" style="float: right;">Function index</a>',
            '<h1><span class="function-name">' + name + '</span> - performance analysis</h1>',
            '' if function.name == function.longname else '<h3> - <span class="function-name">' + function.longname + '</span></h3>',
            '<div class="header-area">',
            '<div class="caller-list">',
            caller_table,
            '</div>',
            '<div class="loop-list">',
            loop_table,
            '</div>',
            '</div>',
            '<div class="show-if-medium tab-control">',
            '<a class="button" onclick=\'select_tab("small", "cfg");select_tab("medium", "cfg-asm");\' >CFG/ASM</a>',
            '<a class="button" onclick=\'select_tab("small", "listing");select_tab("medium", "listing");\' >Source</a>',
            '</div>',
            '<div class="show-if-small tab-control">',
            '<a class="button" onclick=\'select_tab("medium", "cfg-asm");select_tab("small", "cfg");\' >CFG</a>',
            '<a class="button" onclick=\'select_tab("medium", "cfg-asm");select_tab("small", "asm");\' >ASM</a>',
            '<a class="button" onclick=\'select_tab("medium", "listing");select_tab("small", "listing");\' >Source</a>',
            '</div>',
            '<div class="main-area">',
            '<div class="tab-medium" data-selected data-tab-id="cfg-asm">',
            '<div class="asm-svg tab-small" data-tab-id="cfg" data-selected>',
            '<h3 title="Graph showing the basic blocks in the function and how ',
            'control flow passes between them. Loops and function calls are ',
            'highlighted as well as the function entry and exit.">Control flow graph</h3>',
            dot,
            '</div>',
            '<div class="asm-table tab-small" data-tab-id="asm">',
            table,
            '</div>',
            '</div>',
            '<div data-tab-id="listing" class="tab-medium">',
            '<div data-tab-id="listing" class="code-listing tab-small"'
            + '">',
            listing,
            '</div>',
            '</div>',
            '</div>',
            '<script>',
                'var found = false;',
                'if (window.location.hash.startsWith(\'#\')) {',
                    'const els = document.querySelectorAll(\'.asm-table a[name="\' + window.location.hash.substr(1) + \'"]\');',
                    'if (els.length == 1 && els[0].parentElement.parentElement.onclick) {',
                        'setTimeout(() => {',
                        'select_asm(parseInt(window.location.hash.substr(1), 16));',
                        'els[0].parentElement.parentElement.onclick();',
                        '}, 0);',
                        'found = true;',
                    '}',
                '}',
                'if (!found) {',
                    'setTimeout(() => {',
                    ('' if i.line is None else 'select_line(' + str(i.line.id) + ');'),
                    'select_asm(' + str(i.raw.address) + ');',
                    'select_block(' + str(i.block.offset) + ');',
                    '}, 0);',
                '}',
            '</script>',
        ]))

    def function_filename(self, function):
        if function.do_render:
            return safePath(function.name) + ".html"
        else: return None

