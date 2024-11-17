def divide_with_exception(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return "Cannot divide by zero"
