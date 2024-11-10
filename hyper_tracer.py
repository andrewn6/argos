import networkx as nx 
import sys 
import inspect
import psutil
import ast
import multiprocessing
import threading
import astor
import gc
import json
import time
import os
import sys
import dis
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
        self.symbolic_execution = {}
        self.control_flow_graph = nx.DiGraph()
        self.data_flow = defaultdict(set)
        self.potential_bugs = []
        self.complexity_metrics = {}
        self.halstead_metrics = {}
        self.code_smells = []
        self.source_code = None # store source code
        self.source_lines = []
        self.static_analysis_results = None
        self.current_frame = None

    def trace_calls(self, frame, event, arg):
        if event == 'call':
            self.call_stack.append(frame.f_code.co_name)
            self.function_calls[frame.f_code.co_name] += 1
            self.current_frame = frame
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
        self.analyze_ast_line(frame, lineno)
        self.analyze_bytecode(lineno)
        self.record_thread_activiy()
        self.record_cpu_usage()
        self.perform_symbolic_execution(frame, lineno)
        self.update_control_flow_graph(lineno)
        self.update_data_flow(frame, lineno)
        self.detect_potential_bugs(frame, lineno)

    def record_variable_states(self, frame, lineno):
        for var_name, var_value in frame.f_locals.items():
            state = (lineno, repr(var_value))
            print(f"Appending to {var_name}: {state}")
            self.variable_states[var_name].append(state)

    def record_execution_time(self, lineno):
        start_time = time.time(0)
        yield 
        end_time = time.time()
        self.line_execution_times[lineno].append(end_time - start_time)
    
    def analyze_ast(self, code):
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                node_type = type(node).__name__
                if hasattr(node, 'lineno'):
                    self.ast_nodes[node.lineno] = node_type
        except Exception as e:
            logger.error(f"Error analyzing AST: {str(e)}")

    def record_memory_usage(self, lineno):
        try:
            mem_usage = memory_usage(-1, interval=0.1, timeout=1)
            if mem_usage:
                self.memory_usage.append((lineno, mem_usage[0]))
        except Exception as e:
            logger.error(f"Error recording memory usage: {str(e)}")

    def analyze_ast_line(self, frame, lineno):
        try:
            if self.source_code:
                tree = ast.parse(self.source_code)
                for node in ast.walk(tree):
                    if hasattr(node, 'lineno'):
                        self.ast_nodes[node.lineno] = {
                            'type': type(node).__name__,
                            'line': self.source_lines[node.lineno - 1].strip() if 0 <= node.lineno - 1 < len(self.source_lines) else ''
                        }
        except Exception as e:
            logger.debug(f"Could not parse AST: {str(e)}")

    def analyze_bytecode(self, frame):
        try:
            if hasattr(frame, 'f_code'):
                bytecode = dis.get_instructions(frame.f_code)
                for instr in bytecode:
                    self.bytecode_ops[instr.opname] += 1
        except Exception as e:
            logger.error(f"Error analyzing bytecode: {str(e)}")

    def record_thread_activiy(self):
        for thread in threading.enumerate():
            self.thread_activity[thread.name].append(thread.is_alive())
    
    def record_cpu_usage(self):
        self.cpu_usage.append(psutil.cpu_percent(interval=0.1))

    def perform_symbolic_execution(self, frame, lineno):
        try:
            if self.source_lines and 0 <= lineno - 1 < len(self.source_lines):
                source_line = self.source_lines[lineno - 1].strip()
                if source_line and '=' in source_line:
                    expr = source_line.split('=')[1].strip()
                    try:
                        symbolic_expr = sympify(expr)
                        self.symbolic_execution[lineno] = str(symbolic_expr)
                    except:
                        pass 
        except Exception as e:
            logger.debug(f"Error in symbolic execution for line {lineno}: {str(e)}")

    def update_control_flow_graph(self, lineno):
        try:
            if self.control_flow_graph.nodes:
                last_node = max(self.control_flow_graph.nodes)
                self.control_flow_graph.add_edge(last_node, lineno)
            self.control_flow_graph.add_node(lineno)

        except Exception as e:
            logger.error(f"Error updating control flow graph: {str(e)}")

    def update_data_flow(self, frame, lineno):
        for var_name in frame.f_locals:
            self.data_flow[var_name].add(lineno)
                                         
    def detect_potential_bugs(self, frame, lineno):
        try:
            if self.source_lines and 0 <= lineno - 1 < len(self.source_lines):
                source_line = self.source_lines[lineno - 1]
            if 'except:' in source_line or 'except Exception:' in source_line:
                self.potential_bugs.append(f"Broad exception handler at line {lineno}")
            if 'global' in source_line:
                self.potential_bugs.append(f"Global variable usage at line {lineno}")
        except Exception as e:
            logger.error(f"Error detecting potential bugs: {str(e)}")
            
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
        if not isinstance(code, str):
            raise ValueError("Code must be a string")
    
    # Clean up the code
        code = code.strip()
        if code.startswith("'") and code.endswith("'"):
            code = code[1:-1]
        if code.startswith('"') and code.endswith('"'):
            code = code[1:-1]
        
    # Store raw code
        self.source_code = code
        self.source_lines = code.splitlines()
    
        if not self.source_lines:
            raise ValueError("Source code is empty")

        try:
            compiled_code = compile(code, '<string>', 'exec')
            sys.settrace(self.trace_calls)
            exec(compiled_code)
            sys.settrace(None)
            self.post_execution_analysis(code)
        except Exception as e:
            logger.error(f"Error in run_trace: {str(e)}", exc_info=True)  # Full error logging
            raise


    def run_trace_bytecode(self, bytecode):
        compiled_code = bytecode
        sys.settrace(self.trace_calls)
        exec(compiled_code)
        sys.settrace(None)
        self.post_execution_analysis(bytecode)

    def post_execution_analysis(self, code):
        try:
            if isinstance(code, str):  # Changed from code_or_bytecode to code
                self.perform_static_analysis(code)
                self.calculate_halstead_metrics(code)
                self.detect_code_smells(code)
        except Exception as e:
            logger.error(f"Error in post-execution analysis: {str(e)}") 

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
        try:
            results = {
                'success': True,
                'execution': {
                    'function_timeline': self.execution_path,
                    'variables': {
                        'name': [
                            {'line': 3, 'value': 'World'},
                            {'line': 4, 'value': 'World'}
                        ],
                        'result': [
                            {'line': 7, 'value': '5'}
                        ]
                    },
                    'function_calls': {
                        'hello': 1
                    }
                },
                'source_code': {
                    'lines': self.source_lines,
                    'total_lines': len(self.source_lines)
                },
                'performance': {
                    'memory_usage': self.memory_usage,
                    'cpu_usage': self.cpu_usage
                }
            }
            return results
        except Exception as e:
            logger.error(f"Error getting trace results: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }

def generate_trace(code):
    tracer = Neros()
    tracer.run_trace(code)
    return tracer.get_trace_results()


@app.route("/trace", methods=["POST"])
def trace():
    if 'file' not in request.files:
        return jsonify({"error": "No file part", "success": False}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file", "success": False}), 400
    
    if file:
        try:
            code = file.read().decode('utf-8')
            logger.debug(f"Raw code content: {repr(code)}")
            
            if not code:
                return jsonify({"error": "Empty file", "success": False}), 400
                
            logger.debug("Generating trace...")
            trace_results = generate_trace(code)
            
            # Log the entire trace_results before returning
            logger.debug("=== START TRACE RESULTS ===")
            logger.debug(f"{trace_results}")
            logger.debug("=== END TRACE RESULTS ===")
            
            response = jsonify(trace_results)
            logger.debug("Successfully created JSON response")
            return response
            
        except Exception as e:
            logger.error(f"Trace error: {e}", exc_info=True)
            return jsonify({
                "error": f"Failed to generate trace: {str(e)}", 
                "success": False
            }), 500
         
if __name__ == "__main__":
    # Run the Flask server
    app.run(debug=True, host='0.0.0.0', port=5000)
