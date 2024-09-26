import random
from pyelliptic import ECC

def generate_curve_parameters():
    """Generates a random 521-bit elliptic curve and returns its parameters."""
    curve = ECC.generate_random_curve(field_size=521)
    return curve.a, curve.b, curve.p, curve.g

def get_user_input(num_users):
    """Gets user input for a point and a number, considering the number of users."""
    points = []
    numbers = []
    for i in range(num_users):
        print(f"\nUser {i+1} input:")
        x_str = input("Enter x-coordinate of point (integer): ")
        y_str = input("Enter y-coordinate of point (integer): ")
        try:
            x = int(x_str)
            y = int(y_str)
        except ValueError:
            print("Invalid input. Please enter integers.")
            continue
        point = ECC.Point(curve, x, y)
        points.append(point)

        number_str = input("Enter a number between 1 and the number of points on the curve: ")
        try:
            number = int(number_str)
            if not 1 <= number <= curve.order():
                print("Invalid input. Number must be between 1 and the order of the curve.")
                continue
        except ValueError:
            print("Invalid input. Please enter an integer.")
            continue
        numbers.append(number)
    return points, numbers

def calculate_sum(points, numbers):
    """Calculates the sum of scalar multiplications of points."""
    result = ECC.Point(curve, 0, 0)  # Initialize result point
    for point, number in zip(points, numbers):
        result = result + (number * point)
    return result

if __name__ == "__main__":
    # Disable visual interface due to security limitations (explained below)
    print("Visual interface disabled due to security limitations in Python GUI libraries.")
    print("This program provides text-based interaction.")

    # Generate elliptic curve parameters
    curve_a, curve_b, curve_p, curve_g = generate_curve_parameters()

    # Get number of users
    while True:
        num_users_str = input("Enter the number of users (2 or 3): ")
        try:
            num_users = int(num_users_str)
            if num_users in (2, 3):
                break
            else:
                print("Invalid input. Please enter 2 or 3.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    # Display curve parameters
    print("\nCurve parameters:")
    print(f"a: {curve_a}")
    print(f"b: {curve_b}")
    print(f"p: {curve_p}")
    print(f"Generator point (g): ({curve_g.x}, {curve_g.y})")

    # Get user input for points and numbers
    points, numbers = get_user_input(num_users)

    # Calculate sum
    result = calculate_sum(points, numbers)

    # Display result
    print("\nResulting point:")
    print(f"({result.x}, {result.y})")
