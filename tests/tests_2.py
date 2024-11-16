def fibonacci(n):
    if n <= 1:
        return n
    else:
        return (fibonacci(n-1) + fibonacci(n-2))

def factorial(n):
    if n == 0:
        return 1
    else:
        return n * factorial(n-1)

def binary_search(arr, target):
    left, right = 0, len(arr) - 1
    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return -1

def merge_sort(arr):
    if len(arr) > 1:
        mid = len(arr) // 2
        left_half = arr[:mid]
        right_half = arr[mid:]

        merge_sort(left_half)
        merge_sort(right_half)

        i = j = k = 0

        while i < len(left_half) and j < len(right_half):
            if left_half[i] < right_half[j]:
                arr[k] = left_half[i]
                i += 1
            else:
                arr[k] = right_half[j]
                j += 1
            k += 1

        while i < len(left_half):
            arr[k] = left_half[i]
            i += 1
            k += 1

        while j < len(right_half):
            arr[k] = right_half[j]
            j += 1
            k += 1

def main():
    print("Fibonacci sequence:")
    for i in range(10):
        print(fibonacci(i), end=" ")
    print("\n")

    print("Factorials:")
    for i in range(10):
        print(factorial(i), end=" ")
    print("\n")

    arr = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
    print("Binary search:")
    print(binary_search(arr, 9))
    print(binary_search(arr, 20))
    print("\n")

    print("Merge sort:")
    unsorted_list = [5, 2, 4, 6, 1, 3, 2, 6]
    print("Before sorting:", unsorted_list)
    merge_sort(unsorted_list)
    print("After sorting:", unsorted_list)

if __name__ == "__main__":
    main()
