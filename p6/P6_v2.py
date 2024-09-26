import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

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

ventana = tk.Tk()
ventana.title("Firma Digital")

tk.Label(ventana, text="Clave Pública Generada:").pack()
clave_publica = tk.StringVar()
tk.Entry(ventana, textvariable=clave_publica, width=50, state="readonly").pack(pady=5)

tk.Label(ventana, text="Firma Calculada:").pack()
firma = tk.StringVar()
tk.Entry(ventana, textvariable=firma, width=50, state="readonly").pack(pady=5)

boton_cargar = tk.Button(ventana, text="Cargar Texto y Firmar", command=firmar)
boton_cargar.pack(pady=10)

boton_verificar = tk.Button(ventana, text="Verificar Firma", command=verificar)
boton_verificar.pack(pady=10)

ventana.mainloop()
