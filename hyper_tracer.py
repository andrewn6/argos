import networkx as nx 
import sys 
import inspect
import psutil
import ast
import multiprocessing
import threading
import astor
import gc
import time
import os
import sys 
from io import StringIO
from pylint import run_pylint
from memory_profiler import memory_usage
from collections import defaultdict 
from radon.complexity import cc_visit
from radon.metrics import h_visit
from radon.raw import analyze
from sympy import sympify, solve
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import logging 
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads' 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class Neros:
    def __init__(self):
        self.call_stack = []
        self.variable_states = defaultdict(list)
        self.execution_path = []
        self.function_calls = defaultdict(int)
        self.line_execution_times = defaultdict(list)
        self.memory_usage = []
        self.ast_nodes = {}
        self.bytecode_ops = defaultdict(int)
        self.thread_activity = defaultdict(list)
        self.cpu_usage = []
        self.symbolic_execution = []
        self.control_flow_graph = nx.DiGraph()
        self.data_flow = defaultdict(set)
        self.potential_bugs = []a
        self.complexity_metrics = {}
        self.halstead_metrics = {}
        self.code_smells = []
        self.source_code = None # store source code
        self.source_lines = []

    def trace_calls(self, frame, event, arg):
        if event == 'call':
            self.call_stack.append(frame.f_code.co_name)
            self.function_calls[frame.f_code.co_name] += 1
            self.analyze_function_complexity(frame)
        elif event == 'return':
            self.call_stack.pop()
        return self.trace_lines
    
    def trace_lines(self, frame, event, arg):
        if event != 'line':
            return 

        lineno = frame.f_lineno 
        filename = frame.f_code.co_filename 
        function_name = frame.f_code.co_name 

        self.execution_path.append((filename, function_name, lineno))
        self.record_variable_states(frame, lineno)
        self.record_execution_time(lineno)
        self.record_memory_usage(lineno)
        self.analyze_ast(frame, lineno)
        self.analyze_bytecode(lineno)
        self.record_thread_activiy()
        self.record_cpu_usage()
        self.perform_symbolic_execution(frame, lineno)
        self.update_control_flow_graph(lineno)
        self.update_data_flow(frame, lineno)
        self.detect_potential_bugs(frame, lineno)

    def record_variable_states(self, frame, lineno):
        for var_name, var_value in frame.f_locals.items():
            print(f"Appending to {var_name}: {(lineno, repr(var_value))}")
            self.variable_states[var_name].append([lineno, repr(var_value)])

    def record_execution_time(self, lineno):
        start_time = time.time(0)
        yield 
        end_time = time.time()
        self.line_execution_times[lineno].append(end_time - start_time)

    def record_memory_usage(self, lineno):
        self.memory_usage.append(lineno, memory_usage(0))

    def analyze_ast(self, frame, lineno):
        source_line = inspect.getsource(frame).split('\n')[lineno - frame.f_code.co_firstlineno]
        try:
            node = ast.parse(source_line.strip()).body[0]
            self.ast_nodes[lineno] = type(node).__name__
        except:
            pass

    def analyze_bytecode(self, frame):
        bytecode = dis.Bytecode(frame.f_code)
        for instr in bytecode:
            self.bytecode_ops[instr.opname]

    def record_thread_activiy(self):
        for thread in threading.enumerate():
            self.thread_activity[thread.name].append(thread.is_alive())
    
    def record_cpu_usage(self):
        self.cpu_usage.append(psutil.cpu_percent(interval=0.1))

    def perform_symbolic_execution(self, frame, lineno):
        try: 
            source_line = inspect.getsource(frame).split('\n'[lineno - frame.f_code.co_firstlineno])
            expr = sympify(source_line.strip())
            solution = solve(expr)
            self.symbolic_execution[lineno] = str(solution)
        except:
            pass
    def update_control_flow_graph(self, lineno):
        if self.control_flow_graph.nodes:
            last_node = max(self.control_flow_graph.nodes)
            self.control_flow_graph.add_edge(last_none, lineno)
        self.control_flow_graph.add_node(lineno)

    def update_data_flow(self, frame, lineno):
        for var_name in frame.f_locals:
            self.data_flow[var_name].add(lineno)
                                         
    def detect_potential_bugs(self, frame, lineno):
        source_line = inspect.getsource(frame).split('\n')[lineno - frame.f_code.co_firstlineno]
        if 'except: ' in source_line or 'except Exception:' in source_line:
            self.potential_bugs.append(f"Broad exception handler at line {lineno}")
        if 'global' in source_line:
            self.potential_bugs.append(f"Global variable usage at line {lineno}")

    def analyze_function_complexity(self, frame):
        try:
            func_name = frame.f_code.co_name 
            if self.source_code:
                func_lines = []
                in_function = False
                for line in self.source_lines:
                    if line.strip().startswith(f'def {func_name}'):
                        in_function = True 
                    if in_function:
                        func_lines.append(line)
                    if in_function and not line.strip() and func_lines:
                        break
                if func_lines:
                    func_source = '\n'.join(func_lines)
                    cc_results = cc_visit(func_source)
                    for item in cc_results:
                        self.complexity_metrics[item.name] = item.complexity    
        except Exception as e:
            logger.error(f"Error analyzing function complexity: {str(e)}")

    def run_trace(self, code):
        self.source_code = code 
        self.source_lines = code.splitlines()
        
        try:
            compiled_code = compile(code, '<string>', 'exec')
            sys.settrace(self.trace_calls)
            exec(compiled_code)
            sys.settrace(None)
            self.post_execution_analysis(code)
        except Exception as e:
            logger.error(f"Error in run_trace: {str(e)}")
            raise
    
    def run_trace_bytecode(self, bytecode):
        compiled_code = bytecode
        sys.settrace(self.trace_calls)
        exec(compiled_code)
        sys.settrace(None)
        self.post_execution_analysis(bytecode)

    def post_execution_analysis(self, code):
        if isinstance(code_or_bytecode, str):
            self.analyze_ast(code_or_bytecode)
            self.perform_static_analysis(code_or_bytecode)
            self.calculate_halstead_metrics(code_or_bytecode)
            self.detect_code_smells(code_or_bytecode)
        else:
            self.analyze_bytecode(code_or_bytecode)
            self.perform_static_analysis(code_or_bytecode)
            self.calculate_halstead_metrics(code_or_bytecode)
            self.detect_code_smells(code_or_bytecode) 

    def perform_static_analysis(self, code):
        original_stdout = sys.stdout
        sys.stdout = StringIO()

        run_pylint([code])

        pylint_output = sys.stdout.getvalue()
        sys.stdout = original_stdout

        self.static_analysis_results = pylint_output


    def calculate_halstead_metrics(self, code):
        h_visit_result = h_visit(code)
        self.halstead_metrics = {
            'h1': h_visit_result.h1,
            'h2': h_visit_result.h2,
            'N1': h_visit_result.N1,
            'N2': h_visit_result.N2,
            'vocabulary': h_visit_result.vocabulary,
            'length': h_visit_result.length,
            'calculated_length': h_visit_result.calculate_length,
            'volume': h_visit_result.volume,
            'difficulty': h_visit_result.difficulty,
            'effort': h_visit_result.time,
            'bugs': h_visit_result.bugs,
        }
        
    
    def detect_code_smells(self, code):
        # TODO: implement more detection variables -- currently placeholder 
        if 'import *' in code:
            self.code_smells.append("Wildcard import detected")
        if 'except Exception as e:' in code:
            self.code_smells.append("Broad exception handler detected")

    def get_trace_results(self):
        return {
            'execution_path': self.execution_path,
            'variable_states': dict(self.variable_states),
            'function_calls': dict(self.function_calls),
            'line_execution_times': {k: sum(v) / len(v) for k, v in self.line_execution_times.items()},
            'memory_usage': self.memory_usage,
            'ast_nodes': self.ast_nodes,
            'bytecode_ops': dict(self.bytecode_ops),
            'thread_activity': dict(self.thread_activity),
            'cpu_usage': self.cpu_usage,
            'symbolic_execution': self.symbolic_execution,
            'control_flow_graph': list(self.control_flow_graph.edges()),
            'data_flow': {k: list(v) for k, v in self.data_flow.items()},
            'potential_bugs': self.potential_bugs,
            'complexity_metrics': self.complexity_metrics,
            'static_analysis_results': self.static_analysis_results,
            'code_smells': self.code_smells,
    }

def generate_trace(code):
    tracer = Neros()
    tracer.run_trace(code)
    return tracer.get_trace_results()

@app.route("/trace", methods=["POST"])
def trace():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file:
        try:
            # Read the file content directly from the uploaded file
            code = file.read().decode('utf-8')
            logger.info(f"Successfully read file content, length: {len(code)}")
            
            # Generate trace with the actual source code
            trace_results = generate_trace(code)
            return jsonify(trace_results)
            
        except UnicodeDecodeError:
            try:
                file.seek(0)  # Reset file pointer
                code = file.read().decode('latin-1')
                trace_results = generate_trace(code)
                return jsonify(trace_results)
            except Exception as e:
                return jsonify({"error": f"Failed to read file: {str(e)}"}), 500
        except Exception as e:
            return jsonify({"error": f"Failed to generate trace: {str(e)}"}), 500
                
if __name__ == "__main__":
    # Run the Flask server
    app.run(debug=True, host='0.0.0.0', port=5000)
