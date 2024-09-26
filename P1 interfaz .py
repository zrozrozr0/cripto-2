import numpy as np
import tkinter as tk

def hex_to_bin(hex_string):
    
    #Convierte una cadena hexadecimal en una cadena binaria.
    #Utiliza int para pasarlo a entero, luego el entero a cadena binaria
    #Zfill para rellenar los 0 a la izquierda

    return bin(int(hex_string, 16))[2:].zfill(8)

def bin_to_hex(bin_string):
    
    #Convierte una cadena binaria en una cadena hexadecimal.
    #Utiliza int para pasarlo a entero, luego el entero a cadena hexadecimal
    #Upper para mostrar letras mayúsculas
    
    return hex(int(bin_string, 2))[2:].upper()

def multiply_GF2(a, b):
    
    #Multiplica a y b en GF(2^8).
    
    result = 0
    for i in range(8):      #bucle for para iterar 8 veces (trabajamos con 8 bits)
        if b & 1:           #comprueba el menos significativo sea 1, si es 1 se hace un XOR 
            result ^= a     
        a <<= 1             #desplazar A es como multiplicar A por 2
        if a & 0x100:
            a ^= 0x11B # Este es el polinomio irreducible para GF(2^8)
        b >>= 1             #desplaza B es como dividir sobre 2
    return result

def multiply_hex_GF2(hex_str1, hex_str2):
    
    #el resultado de GF(2^8) se pasa a entero y luego a cadena hexadecimal.
    
    a = int(hex_str1, 16)
    b = int(hex_str2, 16)
    #llama a la funcion principal para que calculo la 
    result = multiply_GF2(a, b)
    return hex(result)[2:].upper()

def calculate():
    #Obtiene los valores de las cajas de la interfaz
    hex_input1 = entry1.get()
    hex_input2 = entry2.get()

    #Llama a la función multiply hex gf2, para calcular el producto
    result_hex = multiply_hex_GF2(hex_input1, hex_input2)

    bin_result = hex_to_bin(result_hex)

    #contruye una represaentacion polinomica, cada bit representa un termino en el polinomio
    polynomial = "" #cadena vacia
    for i in range(len(bin_result)):
        #los coeficientes en del polinomio son 0 y 1
        #se recorre la cadena binaria del resultado
        if bin_result[i] == '1':
            #se construye el polinomio segun encuentre un bit en 1
            if polynomial: #verifica si aun hay terminos del polinomio y despues si hay agrega un +
                polynomial += " + " 
            if i == len(bin_result) - 1: #Verifica si es el ultimo bit en la cadena, es decir el termino independiente
                polynomial += "1" #agrega un 1 al final
            else:
                #si el bit actual no es el ultimo
                polynomial += f"x^{len(bin_result)-1-i}" #calcula el exponente a partir de la posicion del bit
                                    # se calcula restando la posición del bit desde el final de la cadena binaria 

    #resultado del calculo y la representacion del polinomio
    result_label.config(text=f"C(x) = {hex_input1} * {hex_input2} mod 0x11B = {result_hex} = {polynomial}")

# Crear la ventana principal
root = tk.Tk()
root.title("Multiplicación en GF(2^8)")

# Crear y ubicar los widgets en la ventana
label1 = tk.Label(root, text="A(x) =")
label1.grid(row=0, column=0, padx=5, pady=5)
entry1 = tk.Entry(root)
entry1.grid(row=0, column=1, padx=5, pady=5)

label2 = tk.Label(root, text="B(x) =")
label2.grid(row=1, column=0, padx=5, pady=5)
entry2 = tk.Entry(root)
entry2.grid(row=1, column=1, padx=5, pady=5)

calculate_button = tk.Button(root, text="Calcular", command=calculate)
calculate_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

result_label = tk.Label(root, text="")
result_label.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

# Ejecutar la interfaz
root.mainloop()
