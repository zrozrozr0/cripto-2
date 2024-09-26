import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

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

# Función para guardar la clave en un archivo
def guardar(nombre_archivo, contenido):
    with open(nombre_archivo, "wb") as archivo:
        archivo.write(contenido)

# Función para concatenar al final de un archivo
def con(nombre_archivo, contenido):
    with open(nombre_archivo, "ab") as archivo:
        archivo.write(contenido)

# Función para cargar la info desde un archivo
def cargar(nombre_archivo):
    with open(nombre_archivo, "rb") as archivo:
        contenido = archivo.read()
    return contenido

def firmar():
    private_key, public_key, private_pem, public_pem = generar_claves()
    
    # Guardar la clave privada en un archivo
    nombre_privada = "private_key.pem"
    guardar(nombre_privada, private_pem)
    
    # Mostrar la clave pública y guardarla en un archivo
    clave_publica.set(public_pem.decode())
    nombre_publica = "public_key.pem"
    guardar(nombre_publica, public_pem)
    
    # Mostrar un mensaje de confirmación
    messagebox.showinfo("Claves Generadas", "Se han generado y guardado las claves.\nEnvía el archivo 'public_key.pem' a los otros usuarios.")

    # Cargar el texto a firmar
    archivo_firmar = filedialog.askopenfilename(title="Seleccionar archivo a firmar", filetypes=(("Text files", "*.txt"), ("Todos los archivos", "*.*")))
    if not archivo_firmar:
        messagebox.showerror("Error", "No se seleccionó ningún archivo para firmar.")
        return
    
    texto = cargar(archivo_firmar)
    
    # Calcular la firma 
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(texto)
    digest = hasher.finalize()
    sign = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    # Mostrar la firma
    firma.set(sign.hex())
    print(firma)
    # Guardar archivo firmado
    nombre = "archivo_firmado.txt"
    separador='\n'+"---"+'\n'
    separador=bytes(separador,"utf-8")
    guardar(nombre, texto)
    con(nombre, separador)
    con(nombre, sign)
    
def verificar():
    # Cargar la clave pública
    try:
        public_pem = cargar("public_key.pem")
    except FileNotFoundError:
        messagebox.showerror("Error", "No se encontró el archivo 'public_key.pem'.")
        return
    except Exception as e:
        messagebox.showerror("Error", f"Error al cargar la clave pública: {str(e)}")
        return
    
    try:
        public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
    except Exception as e:
        messagebox.showerror("Error", f"Error al decodificar la clave pública: {str(e)}")
        return
    
    # Cargar el archivo firmado y extraer el texto y la firma
    archivo_firmado = filedialog.askopenfilename(title="Seleccionar archivo firmado", filetypes=(("Text files", "*.txt"), ("Todos los archivos", "*.*")))
    if not archivo_firmado:
        messagebox.showerror("Error", "No se seleccionó ningún archivo firmado.")
        return
    
    try:
        contenido = cargar(archivo_firmado)
    except FileNotFoundError:
        messagebox.showerror("Error", f"No se encontró el archivo '{archivo_firmado}'.")
        return
    except Exception as e:
        messagebox.showerror("Error", f"Error al cargar el archivo firmado: {str(e)}")
        return
    
    # Asumimos que la firma está al final del archivo firmado
    firma_len = len(contenido) - 132  # 132 es un ejemplo, ajuste según el tamaño de la firma
    texto, firma = contenido[:firma_len], contenido[firma_len:]
    
    # Calcular el hash del texto
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(texto)
    digest = hasher.finalize()
    
    # Verificar la firma
    try:
        public_key.verify(
            firma,
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        messagebox.showinfo("Verificación", "La firma es válida.")
    except Exception as e:
        messagebox.showerror("Verificación", "La firma no es válida: " + str(e))

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Firma y Verificación")

# Crear los widgets
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

# Ejecutar el bucle principal
ventana.mainloop()
