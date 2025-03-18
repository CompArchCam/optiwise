#!/usr/bin/env python3
import sys

try:
    import graphviz
except ImportError as e:
    print(
"Error: Python 'import graphviz' failed: " + str(e) + "\n"
"       Install python graphviz, perhaps via 'apt install python3-graphviz', to\n"
"       use OptiWISE gui.",
    file=sys.stderr)
    sys.exit(1)

import processor
import render

args = sys.argv[1:]

render_all = False
if len(args) > 0 and args[0] == "--render-all":
    render_all = True
    args = args[1:]


if len(args) != 3:
    print("Error: bad command line for python OptiWISE gui:  " + ' '.join(sys.argv), file=sys.stderr)
    print(args, render_all)
    sys.exit(1)

path_count = args[0]
path_analyze = args[1]
path_gui = args[2]
try:
    file_count = open(path_count)
    file_inst_csv = open(path_analyze + '/inst.csv')
    file_loop_csv = open(path_analyze + '/loop.csv')
    file_structure = open(path_analyze + '/structure.yaml')
except OSError as e:
    print("Error: count not open input: " + str(e), file=sys.stderr)
    sys.exit(1)

try:
    with file_count as a, file_inst_csv as b, file_loop_csv as c, file_structure as d:
        p = processor.Processed(a, b, c, d)
except Exception as e:
    print("Error: count not read or process input: " + str(e), file=sys.stderr)
    sys.exit(1)

output = path_gui + '/'
r = render.Renderer(p)

exit_code = 0

def open_output(path):
    try:
        return open(output + path, 'w')
    except OSError as e:
        print("Error: count not open output : " + str(e), file=sys.stderr)
        exit_code = 1
        return None

for function in p.functions.values():
    function.do_render = render_all or function.samples_inc > 0
try:
    file_index = open_output('index.html')
    if file_index is not None:
        with file_index as f:
            print("Info: output index.html")
            f.write(r.render_functions())
except Exception as e:
    print("Error: count not write output: " + str(e), file=sys.stderr)
    exit_code = 1
for function in p.functions.values():
    if function.do_render:
        func_filename = r.function_filename(function)
        try:
            file_func = open_output(func_filename)
            if file_func is not None:
                with file_func as f:
                    print("Info: output", func_filename)
                    f.write(r.render_function(function))
        except Exception as e:
            print("Error: count not write output: " + str(e), file=sys.stderr)
            exit_code = 1

sys.exit(exit_code)
