def es_primo(numero):
  """
  Función para verificar si un número es primo.

  Parámetros:
    numero: El número a verificar.

  Retorno:
    True si el número es primo, False si no lo es.
  """
  if numero <= 1:
    return False
  for i in range(2, int(numero**0.5) + 1):
    if numero % i == 0:
      return False
  return True

def calcular_generadores(numero):
  """
  Función para calcular la cantidad total de generadores del GF(p) de un número.

  Parámetros:
    numero: El número a calcular.

  Retorno:
    La cantidad total de generadores del GF(p) del número.
  """
  phi_numero = numero - 1
  total_generadores = 0
  for i in range(1, numero):
    if es_primo(i) and phi_numero % i == 0:
      total_generadores += 1
  return total_generadores

def mostrar_tabla(numero, generadores):
  """
  Función para mostrar una tabla con los generadores del GF(p) y su orden.

  Parámetros:
    numero: El número a calcular.
    generadores: Una lista con los generadores del GF(p).
  """
  print(f"Número: {numero}")
  print("-------------------------")
  print("| Generador | Orden |")
  print("-------------------------")
  for i, generador in enumerate(generadores):
    orden = 1
    while (generador ** orden) % numero != 1:
      orden += 1
    print(f"| {generador} | {orden} |")

# Solicitar el número al usuario
numero = int(input("Introduzca un número entero: "))

# Validar que el número sea primo
while not es_primo(numero):
  numero = int(input("El número introducido no es primo. Introduzca un número entero primo: "))

# Calcular la cantidad total de generadores
total_generadores = calcular_generadores(numero)

# Calcular los generadores
generadores = []
for i in range(1, numero):
  if es_primo(i) and (i ** (numero - 1)) % numero == 1:
    generadores.append(i)

# Mostrar la tabla
mostrar_tabla(numero, generadores)
