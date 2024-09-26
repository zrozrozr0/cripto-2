import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import os
import math

class DiffieHellmanGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Diffie-Hellman para tres personas")
        self.current_user = None
        self.curve_params = None
        self.generator_point = None
        self.random_number = None
        self.point = None

        self.generate_button_alicia = tk.Button(master, text="Alicia", command=lambda: self.select_user("Alicia"))
        self.generate_button_alicia.grid(row=0, column=0, padx=10, pady=10)
        self.generate_button_betito = tk.Button(master, text="Betito", command=lambda: self.select_user("Betito"))
        self.generate_button_betito.grid(row=0, column=1, padx=10, pady=10)
        self.generate_button_carlitos = tk.Button(master, text="Carlitos", command=lambda: self.select_user("Carlitos"))
        self.generate_button_carlitos.grid(row=0, column=2, padx=10, pady=10)

        self.show_shared_key_button = tk.Button(master, text="Ver Clave Compartida", command=self.show_shared_key)
        self.show_shared_key_button.grid(row=1, column=1, padx=10, pady=10)

    def select_user(self, user):
        self.current_user = user
        self.generate_curve_params()
        self.show_params()

    def generate_curve_params(self):
        if self.current_user:
            curve = ec.SECP521R1()
            private_key = ec.generate_private_key(curve, default_backend())
            public_key = private_key.public_key()
            self.curve_params = curve
            self.generator_point = public_key
            self.random_number = os.urandom(32)
            self.point = private_key.exchange(ec.ECDH(), public_key)

    def show_params(self):
        self.params_window = tk.Toplevel(self.master)
        self.params_window.title("Parámetros de la curva")

        params_label = tk.Label(self.params_window, text=f"Parámetros de la curva:\n\nNombre de la curva: SECP521R1\n\nPunto generador:\n{self.generator_point.public_numbers().x}\n\nNúmero aleatorio: {int.from_bytes(self.random_number, 'big')}\n\nPrimer punto generado:\n{int.from_bytes(self.point, 'big')}")
        params_label.pack(padx=10, pady=10)

    def show_shared_key(self):
        if not self.curve_params:
            tk.messagebox.showerror("Error", "Debe seleccionar un usuario primero.")
            return

        shared_key = self.calculate_shared_key()
        shared_key_window = tk.Toplevel(self.master)
        shared_key_window.title("Clave Compartida")

        shared_key_label = tk.Label(shared_key_window, text=f"Clave Compartida:\n\n{shared_key}")
        shared_key_label.pack(padx=10, pady=10)

        self.verify_key_length(shared_key, shared_key_window)

    def calculate_shared_key(self):
        if self.curve_params:
            private_key = ec.generate_private_key(self.curve_params, default_backend())
            public_key = private_key.public_key()
            shared_key = private_key.exchange(ec.ECDH(), self.generator_point)
            return shared_key

    def verify_key_length(self, shared_key, window):
        key_length_bits = math.ceil(math.log2(int.from_bytes(shared_key, 'big')))
        verification_label = tk.Label(window, text=f"La longitud de la clave compartida es de aproximadamente {key_length_bits} bits.")
        verification_label.pack(padx=10, pady=10)

def main():
    root = tk.Tk()
    app = DiffieHellmanGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
