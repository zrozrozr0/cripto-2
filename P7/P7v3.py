import tkinter as tk
import json
from base64 import b64encode
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SEPARADOR_IV = b"\n---IV---\n"
SEPARADOR_FIRMA = b"\n---SIGNATURE---\n"
USUARIOS = 2
SHARED_SECRET = None

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

def claves():
    private_key, public_key, private_pem, public_pem = generar_claves()
    global PRIVATE_KEY
    PRIVATE_KEY=private_key
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
    PK_btn.pack_forget()
    if(USUARIOS==3):
        EX1_btn.pack()
    else:
        EXF_btn.pack()

def cambio1():
    archivo_publica = filedialog.askopenfilename(title="Seleccionar clave pública", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
    if not archivo_publica:
        return
    public_pem = cargar(archivo_publica)
    public_key = serialization.load_pem_public_key(public_pem)
    global SHARED_SECRET
    SHARED_SECRET=PRIVATE_KEY.exchange(ec.ECDH(), public_key)
    clave_parcial.set(SHARED_SECRET)

def cambiofinal():
    archivo_publica = filedialog.askopenfilename(title="Seleccionar clave pública", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
    if not archivo_publica:
        return
    public_pem = cargar(archivo_publica)
    public_key = serialization.load_pem_public_key(public_pem)
    global SHARED_SECRET
    SHARED_SECRET=PRIVATE_KEY.exchange(ec.ECDH(), public_key)
    print(SHARED_SECRET)
    shared_secret.set(SHARED_SECRET)
    EXF_btn.pack_forget()
    boton_cargar.pack()
    boton_verificar.pack()
    

def firmar():
    S_lb.pack()
    S_TF.pack(pady="10")
    global SHARED_SECRET
    archivo_firmar = filedialog.askopenfilename(title="Seleccionar archivo a firmar", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if not archivo_firmar:
        return
    texto = cargar(archivo_firmar)
    print(SHARED_SECRET)
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(texto)
    digest = hasher.finalize()
    cipher = AES.new(SHARED_SECRET[:16], AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(texto, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    sign = PRIVATE_KEY.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    firma.set(sign.hex())
    
    nombre_firmado = filedialog.asksaveasfilename(title="Guardar archivo firmado", defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if not nombre_firmado:
        return
    guardar(nombre_firmado, ct.encode('utf-8'))
    con(nombre_firmado, SEPARADOR_IV)
    con(nombre_firmado, iv.encode('utf-8'))
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

# Funcion para preparar para 2 usuarios
def dos_usuarios():
    usr_label.pack_forget()
    boton_2usuarios.pack_forget()
    boton_3usuarios.pack_forget()
    PK_lb.pack()
    PK_tf.pack(pady="10")
    PK_btn.pack()
    EXF_lb.pack()
    EXF_tf.pack(pady="10")

# Funcion para preparar para 2 usuarios
def tres_usuarios():
    USUARIOS=3
    usr_label.pack_forget()
    boton_2usuarios.pack_forget()
    boton_3usuarios.pack_forget()
    PK_lb.pack()
    PK_tf.pack(pady="10")
    PK_btn.pack()
    EX1_lb.pack()
    EX1_tf.pack(pady="10")
    EXF_lb.pack()
    EXF_tf.pack(pady="10")

#Inicia codigo interfaz
ventana = tk.Tk()
ventana.title("Firma Digital")

#seleccionar numero de usuarios
usr_label=tk.Label(ventana, text="Numero de Usuarios:")
usr_label.pack()
boton_2usuarios = tk.Button(ventana, text="2", command=dos_usuarios)
boton_2usuarios.pack()
boton_3usuarios = tk.Button(ventana, text="3", command=tres_usuarios)
boton_3usuarios.pack()

#Generar claves
PK_lb=tk.Label(ventana, text="Clave Pública Generada:")
clave_publica = tk.StringVar()
PK_tf=tk.Entry(ventana, textvariable=clave_publica, width=50, state="readonly")
PK_btn=tk.Button(ventana, text="Generar claves", command=claves)

#Intercambio 1
EX1_lb=tk.Label(ventana, text="Clave Parcial Generada")
clave_parcial = tk.StringVar()
EX1_tf=tk.Entry(ventana, textvariable=clave_parcial, width=50, state="readonly")
EX1_btn=tk.Button(ventana, text="Generar secreto parcial", command=cambio1)

#Intercambio final
EXF_lb=tk.Label(ventana, text="Secreto Compartido Generado")
shared_secret = tk.StringVar()
EXF_tf=tk.Entry(ventana, textvariable=shared_secret, width=50, state="readonly")
EXF_btn=tk.Button(ventana, text="Generar secreto compartido", command=cambiofinal)

#Cifrar y firmar
S_lb=tk.Label(ventana, text="Firma Calculada:")
firma = tk.StringVar()
S_TF=tk.Entry(ventana, textvariable=firma, width=50, state="readonly")
boton_cargar = tk.Button(ventana, text="Cargar Texto y Firmar", command=firmar)

#Verificar
boton_verificar = tk.Button(ventana, text="Verificar Firma", command=verificar)


ventana.mainloop()
