import inspect
import os
import marshal
import types
import unittest
from codegen.simple_function import example_function
from codegen.class_with_methods import ExampleClass
from codegen.loop_with_if import loop_with_if
from codegen.recursive_function import factorial
from codegen.exception_handling import divide_with_exception

class TestPythonBinaries(unittest.TestCase):
    def setUp(self):
        self.binaries_dir = os.path.join(os.path.dirname(__file__), 'binaries')
        os.makedirs(self.binaries_dir, exist_ok=True)

    def test_simple_function(self):
        self.generate_binary(example_function, 'simple_function.pyc')

    def test_class_with_methods(self):
        self.generate_binary(ExampleClass, 'class_with_methods.pyc')

    def test_loop_with_if(self):
        self.generate_binary(loop_with_if, 'loop_with_if.pyc')

    def test_recursive_function(self):
        self.generate_binary(factorial, 'recursive_function.pyc')

    def test_exception_handling(self):
        self.generate_binary(divide_with_exception, 'exception_handling.pyc')

    def generate_binary(self, obj, filename):
        binary_file = os.path.join(self.binaries_dir, filename)
        compiled_code = compile(inspect.getsource(obj), '<string>', 'exec')
        binary_code = marshal.dumps(compiled_code)

        with open(binary_file, 'wb') as f:
            f.write(binary_code)

        self.assert_binary_exists(binary_file)

    def assert_binary_exists(self, binary_file):
        self.assertTrue(os.path.isfile(binary_file))
        self.assertGreater(os.path.getsize(binary_file), 0)

if __name__ == '__main__':
    unittest.main()
