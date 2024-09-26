import sympy

def find_generators(p):
    generators = []
    for g in range(1, p):
        if sympy.is_primitive_root(g, p):
            generators.append(g)
    return generators

def print_table(numbers, order):
    print("Generadores del GF(p):")
    print("Número\tOrden")
    for num in numbers:
        print(f"{num}\t{order}")

def main():
    while True:
        try:
            num = int(input("Introduce un número: "))
            if sympy.isprime(num):
                generators = find_generators(num)
                order = num - 1  # Calculamos el orden como p-1
                print_table(generators, order)
                break
            else:
                print("El número no es primo. Inténtalo de nuevo.")
        except ValueError:
            print("Por favor, introduce un número entero.")

if __name__ == "__main__":
    main()
