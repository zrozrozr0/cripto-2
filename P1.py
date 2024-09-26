import numpy as np
import tkinter as tk

def hex_to_bin(hex_string):
    
    #Convierte el hexadecimal en binario.
    
    return bin(int(hex_string, 16))[2:].zfill(8)

def bin_to_hex(bin_string):
    
    #Convierte binario en hexadecimal.

    return hex(int(bin_string, 2))[2:].upper()

def multiply_GF2(a, b):
  
   #Multiplica los números en GF(2^8).
  
    result = 0
    for i in range(8):
        if   & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B # Polinomio irreducible para GF(2^8)
        b >>= 1
    return result

def multiply_hex_GF2(hex_str1, hex_str2):
    
    #Multiplica dos números hexadecimales en GF(2^8).
 
    a = int(hex_str1, 16)
    b = int(hex_str2, 16)
    result = multiply_GF2(a, b)
    return hex(result)[2:].upper()

def main():
    print("Input:")
    hex_input1 = input("A(x) = ")
    hex_input2 = input("B(x) = ")

    result_hex = multiply_hex_GF2(hex_input1, hex_input2)
    print("Output:")

    # Convertir el resultado a forma de polinomio
    bin_result = hex_to_bin(result_hex)
    polynomial = ""
    for i in range(len(bin_result)):
        if bin_result[i] == '1':
            if polynomial:
                polynomial += " + "
            if i == len(bin_result) - 1:
                polynomial += "1"
            else:
                polynomial += f"x^{len(bin_result)-1-i}"

    print(f"C(x) = {hex_input1} * {hex_input2} mod 0x11B = {result_hex} =", polynomial)

if __name__ == "__main__":
    main()
