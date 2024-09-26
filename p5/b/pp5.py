import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Función para generar una clave privada y su correspondiente clave pública en formato PEM
def generar_claves():
    private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
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
    
    return private_key, private_pem, public_pem

# Función para guardar la clave en un archivo
def guardar_clave(nombre_archivo, clave):
    with open(nombre_archivo, "wb") as archivo:
        archivo.write(clave)

# Función para cargar la clave desde un archivo
def cargar_clave(nombre_archivo):
    with open(nombre_archivo, "rb") as archivo:
        clave = archivo.read()
    return clave

# Función para guardar la clave compartida en un archivo PEM
def guardar_clave_compartidaf(nombre_archivo, clave_compartida):
    pem_content = "-----BEGIN SHARED KEY-----\n" + clave_compartida + "\n-----END SHARED KEY-----\n"
    with open(nombre_archivo, "w") as archivo:
        archivo.write(pem_content)

# Función para generar la clave y comenzar el proceso
def generar_clave_y_comenzar():
    # Generar las claves para el usuario actual
    private_key, private_pem, public_key = generar_claves()
    
    # Guardar la clave privada en un archivo
    nombre_privada = "private_key.pem"
    guardar_clave(nombre_privada, private_pem)
    
    # Mostrar la clave pública y guardarla en un archivo
    clave_publica.set(public_key.decode())
    nombre_publica = "public_key.pem"
    guardar_clave(nombre_publica, public_key)
    
    # Mostrar un mensaje de confirmación
    messagebox.showinfo("Claves Generadas", "Se han generado y guardado las claves.\nEnvía el archivo 'public_key.pem' a los otros usuarios.")
    
    # Deshabilitar el botón de generar
    boton_generar.config(state="disabled")

# Función para cargar las claves públicas de los otros usuarios desde archivos
def cargar_claves_usuarios():
    # Cargar las claves públicas de los otros usuarios desde archivos
    archivo_publica_2 = filedialog.askopenfilename(title="Seleccionar clave pública del usuario 2", filetypes=(("PEM files", "*.pem"), ("Todos los archivos", "*.*")))
    #archivo_publica_3 = filedialog.askopenfilename(title="Seleccionar clave pública del usuario 3", filetypes=(("PEM files", "*.pem"), ("Todos los archivos", "*.*")))
    
    # Cargar las claves públicas desde los archivos
    public_key_2 = cargar_clave(archivo_publica_2)
    #public_key_3 = cargar_clave(archivo_publica_3)
    
    # Calcular la clave compartida para este usuario
    private_key = cargar_clave("private_key.pem")
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )
    
    public_key_2 = serialization.load_pem_public_key(
        public_key_2,
        backend=default_backend()
    )
    
    #public_key_3 = serialization.load_pem_public_key(
    #    public_key_3,
    #    backend=default_backend()
    #)
    
    shared_key = private_key.exchange(ec.ECDH(), public_key_2)
    #shared_key = private_key.exchange(ec.ECDH(), public_key_3)
    #GEN SHARED PEM
    shared_pem = shared_key.shared_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    name_shared="shared-key.pem"
    guardar_clave("shared-key",shared_pem)
    # Mostrar la clave compartida
    shared_key_hex = shared_key.hex()
    clave_compartida.set(shared_key_hex)
    guardar_clave_compartidaf("shared_key.pem", shared_key_hex)
    pem_content = "-----BEGIN SHARED KEY-----\n" + shared_key_hex + "\n-----END SHARED KEY-----\n"
    texto_clave_compartida.delete(1.0, tk.END)
    texto_clave_compartida.insert(tk.END, pem_content)

def guardar_clave_compartida():
    shared_key_hex = clave_compartida.get()
    guardar_clave_compartidaf("shared_key.pem", shared_key_hex)

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Intercambio de Claves")

# Crear los widgets
tk.Label(ventana, text="Clave Pública Generada:").pack()
clave_publica = tk.StringVar()
tk.Entry(ventana, textvariable=clave_publica, width=50, state="readonly").pack(pady=5)

boton_generar = tk.Button(ventana, text="Generar Clave", command=generar_clave_y_comenzar)
boton_generar.pack(pady=10)

tk.Label(ventana, text="Clave Compartida Calculada:").pack()

texto_clave_compartida = tk.Text(ventana, height=5, width=50)
texto_clave_compartida.pack()

boton_cargar = tk.Button(ventana, text="Cargar Claves Públicas", command=cargar_claves_usuarios)
boton_cargar.pack(pady=10)

# Botón para guardar la clave compartida
boton_guardar_clave = tk.Button(ventana, text="Guardar Clave Compartida", command=guardar_clave_compartida)
boton_guardar_clave.pack(pady=10)

# Variable para la clave compartida
clave_compartida = tk.StringVar()

# Ejecutar el bucle principal
ventana.mainloop()
