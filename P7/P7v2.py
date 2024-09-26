import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tinyec import registry, ec as tinyec
import secrets
import base64
import os

SEPARADOR_FIRMA = b"\n---SIGNATURE---\n"

def generar_claves():
    private_key = ec.generate_private_key(ec.SECP521R1())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, public_key, private_pem, public_pem

def guardar(nombre_archivo, contenido):
    with open(nombre_archivo, "wb") as archivo:
        archivo.write(contenido)

def con(nombre_archivo, contenido):
    with open(nombre_archivo, "ab") as archivo:
        archivo.write(contenido)

def cargar(nombre_archivo):
    with open(nombre_archivo, "rb") as archivo:
        contenido = archivo.read()
    return contenido

def firmar():
    private_key, public_key, private_pem, public_pem = generar_claves()
    
    nombre_privada = filedialog.asksaveasfilename(title="Guardar clave privada", defaultextension=".pem", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
    if not nombre_privada:
        return
    guardar(nombre_privada, private_pem)
    
    clave_publica.set(public_pem.decode())
    nombre_publica = filedialog.asksaveasfilename(title="Guardar clave pública", defaultextension=".pem", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
    if not nombre_publica:
        return
    guardar(nombre_publica, public_pem)
    
    messagebox.showinfo("Claves Generadas", "Se han generado y guardado las claves.\nEnvía el archivo 'public_key.pem' a los otros usuarios.")

    archivo_firmar = filedialog.askopenfilename(title="Seleccionar archivo a firmar", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if not archivo_firmar:
        return
    texto = cargar(archivo_firmar)
    
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(texto)
    digest = hasher.finalize()
    sign = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    firma.set(sign.hex())
    
    nombre_firmado = filedialog.asksaveasfilename(title="Guardar archivo firmado", defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if not nombre_firmado:
        return
    guardar(nombre_firmado, texto)
    con(nombre_firmado, SEPARADOR_FIRMA)
    con(nombre_firmado, sign)

def verificar():
    archivo_publica = filedialog.askopenfilename(title="Seleccionar clave pública", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
    if not archivo_publica:
        return
    public_pem = cargar(archivo_publica)
    public_key = serialization.load_pem_public_key(public_pem)
    
    archivo_firmado = filedialog.askopenfilename(title="Seleccionar archivo firmado", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if not archivo_firmado:
        return
    contenido = cargar(archivo_firmado)
    
    try:
        texto, firma_bin = contenido.split(SEPARADOR_FIRMA)
    except ValueError:
        messagebox.showerror("Error", "El archivo firmado no tiene el formato esperado.")
        return
    
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(texto)
    digest = hasher.finalize()
    
    try:
        public_key.verify(
            firma_bin,
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        messagebox.showinfo("Verificación Exitosa", "La firma es válida.")
    except Exception as e:
        messagebox.showerror("Verificación Fallida", f"La firma no es válida: {e}")

def generar_clave_aes(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def cifrar_aes(texto, password):
    salt = os.urandom(16)
    key = generar_clave_aes(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(texto) + padder.finalize()
    cifrado = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + cifrado).decode('utf-8')

def descifrar_aes(cifrado_base64, password):
    cifrado = base64.b64decode(cifrado_base64.encode('utf-8'))
    salt = cifrado[:16]
    iv = cifrado[16:32]
    key = generar_clave_aes(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(cifrado[32:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    texto = unpadder.update(padded_data) + unpadder.finalize()
    return texto

def cifrar():
    archivo_cifrar = filedialog.askopenfilename(title="Seleccionar archivo a cifrar", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if not archivo_cifrar:
        return
    texto = cargar(archivo_cifrar)
    password = simpledialog.askstring("Contraseña", "Introduce una contraseña para cifrar:", show='*')
    if not password:
        return
    texto_cifrado = cifrar_aes(texto, password)
    nombre_cifrado = filedialog.asksaveasfilename(title="Guardar archivo cifrado", defaultextension=".enc", filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
    if not nombre_cifrado:
        return
    guardar(nombre_cifrado, texto_cifrado.encode())

def descifrar():
    archivo_descifrar = filedialog.askopenfilename(title="Seleccionar archivo a descifrar", filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
    if not archivo_descifrar:
        return
    texto_cifrado = cargar(archivo_descifrar).decode()
    password = simpledialog.askstring("Contraseña", "Introduce la contraseña para descifrar:", show='*')
    if not password:
        return
    try:
        texto_descifrado = descifrar_aes(texto_cifrado, password)
        nombre_descifrado = filedialog.asksaveasfilename(title="Guardar archivo descifrado", defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not nombre_descifrado:
            return
        guardar(nombre_descifrado, texto_descifrado)
        messagebox.showinfo("Éxito", "El archivo se ha descifrado correctamente.")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo descifrar el archivo: {e}")

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

    messagebox.showinfo("Success", "Public key saved successfully")

def SecondKey(): #Generates the second key to send
    global curve
    global PrivKey1
    compressedPubKey = str(Kc.get())
    x, y = decompress(compressedPubKey)
    public2 = tinyec.Point(curve, x, y)

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
    public3 = tinyec.Point(curve, x, y)

    # Calculation of the shared key 1
    first_SharedKey = PrivKey1 * public3

    KeyShared2 = compress(first_SharedKey)
    
    # File name
    file_name = "LLaveCompartidaFinal.txt"

    # Write the compressed variable to the file
    with open(file_name, "w") as file:
        file.write(KeyShared2)

# Tkinter window
ventana = tk.Tk()  
ventana.geometry("500x500") 
ventana.title("Firma Digital y Cifrado")

tk.Label(ventana, text="Clave Pública Generada:").pack()
clave_publica = tk.StringVar()
tk.Entry(ventana, textvariable=clave_publica, width=50, state="readonly").pack(pady=5)

tk.Label(ventana, text="Firma Calculada:").pack()
firma = tk.StringVar()
tk.Entry(ventana, textvariable=firma, width=50, state="readonly").pack(pady=5)

boton_firmar = tk.Button(ventana, text="Firmar Texto", command=firmar)
boton_firmar.pack(pady=10)

boton_verificar = tk.Button(ventana, text="Verificar Firma", command=verificar)
boton_verificar.pack(pady=10)

boton_cifrar = tk.Button(ventana, text="Cifrar Archivo", command=cifrar)
boton_cifrar.pack(pady=10)

boton_descifrar = tk.Button(ventana, text="Descifrar Archivo", command=descifrar)
boton_descifrar.pack(pady=10)

button1 = tk.Button(ventana, text="Calcular clave pública", command=FirstKey)
button1.pack(pady=10)

Kc = tk.StringVar()
entry1 = tk.Entry(ventana, textvariable=Kc, width=50)
entry1.pack(pady=5)
text1 = tk.Label(ventana, text="Clave pública de otro usuario:")
text1.pack(pady=1)
button2 = tk.Button(ventana, text="Calcular clave compartida 1", command=SecondKey)
button2.pack(pady=10)

Kcb = tk.StringVar()
entry2 = tk.Entry(ventana, textvariable=Kcb, width=50)
entry2.pack(pady=5)
text2 = tk.Label(ventana, text="Clave pública compartida:")
text2.pack(pady=1)
button3 = tk.Button(ventana, text="Calcular clave compartida final", command=ThirdKey)
button3.pack(pady=10)

ventana.mainloop()
