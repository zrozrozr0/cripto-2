from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tinyec import registry
import secrets
from tinyec import ec

global PrivKey1
global PubKey1
global curve

def compress(pubKey):
    x_hex = hex(pubKey.x)[2:]
    y_hex = hex(pubKey.y)[2:]
    compressed = x_hex + y_hex
    return compressed

def decompress(compressedPubKey):
    x = int(compressedPubKey[:128], 16)
    y = int(compressedPubKey[128:], 16)
    return x, y

def FirstKey(): #Generates public and private keys
    global PrivKey1
    global PubKey1
    global curve
    curve = registry.get_curve('brainpoolP512r1')
    
    # Generation of private and public key of the first user
    PrivKey1 = secrets.randbelow(curve.field.n)
    PubKey1 = PrivKey1 * curve.g

    # Ensure the public key is compressed correctly
    PubKey1_compressed = compress(PubKey1)
    while len(PubKey1_compressed) != 256:
        PrivKey1 = secrets.randbelow(curve.field.n)
        PubKey1 = PrivKey1 * curve.g
        PubKey1_compressed = compress(PubKey1)
    
    # File name
    file_name = "Llave_publica.txt"

    # Write the compressed variable to the file
    with open(file_name, "w") as file:
        file.write(PubKey1_compressed)
        file.close()

    messagebox.showinfo("Success", "Public key saved successfully")

def SecondKey(): #Generates the second key to send
    global curve
    global PrivKey1
    compressedPubKey = str(Kc.get())
    x, y = decompress(compressedPubKey)
    public2 = ec.Point(curve, x, y)

    # Calculation of the shared key 1
    first_SharedKey = PrivKey1 * public2

    KeyShared1 = compress(first_SharedKey)
    
    # File name
    file_name = "Llave_compartida.txt"

    # Write the compressed variable to the file
    with open(file_name, "w") as file:
        file.write(KeyShared1)
    
    messagebox.showinfo("Success", "Shared key saved successfully")


def ThirdKey(): #Generates the final key for Diffie-Hellman
    global curve
    global PrivKey1
    compressedPubKey = str(Kcb.get())
    x, y = decompress(compressedPubKey)
    public3 = ec.Point(curve, x, y)

    # Calculation of the shared key 1
    first_SharedKey = PrivKey1 * public3

    KeyShared2 = compress(first_SharedKey)
    
    # File name
    file_name = "LLaveCompartidaFinal.txt"

    # Write the compressed variable to the file
    with open(file_name, "w") as file:
        file.write(KeyShared2)

# Tkinter window
window = Tk()  
window.geometry("350x300") 
window.title("P5")

button1 = Button(window, text="Calculate public key", command=FirstKey)
button1.grid(row=4, column=1, ipadx=10, ipady=5)

Kc = StringVar()
entry1 = Entry(window, textvariable=Kc, width=50)
entry1.grid(row=6, column=1)
text1 = Label(window, text="K1:")
text1.grid(row=6, column=0, padx=5, pady=1)
button2 = Button(window, text="Calculate K2", command=SecondKey)
button2.grid(row=7, column=1, ipadx=10, ipady=5)

Kcb = StringVar()
entry2 = Entry(window, textvariable=Kcb, width=50)
entry2.grid(row=9, column=1)
text2 = Label(window, text="K2:")
text2.grid(row=9, column=0, padx=5, pady=1)
button3 = Button(window, text="Generate shared key", command=ThirdKey)
button3.grid(row=10, column=1, ipadx=10, ipady=5)

window.mainloop()