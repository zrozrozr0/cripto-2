from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def save_key_to_file(key, filename):
    with open(filename, "wb") as f:
        f.write(key)

# Generar las claves para las tres entidades
alice_private_key, alice_public_key = generate_key_pair()
bob_private_key, bob_public_key = generate_key_pair()
charlie_private_key, charlie_public_key = generate_key_pair()

# Guardar las claves privadas en archivos
save_key_to_file(alice_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
), "alice_private_key.pem")

save_key_to_file(bob_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
), "bob_private_key.pem")

save_key_to_file(charlie_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
), "charlie_private_key.pem")

# Guardar las claves públicas en archivos
save_key_to_file(alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
), "alice_public_key.pem")

save_key_to_file(bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
), "bob_public_key.pem")

save_key_to_file(charlie_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
), "charlie_public_key.pem")

# Derivar los secretos compartidos
alice_to_bob_shared_secret = derive_shared_secret(alice_private_key, bob_public_key)
alice_to_charlie_shared_secret = derive_shared_secret(alice_private_key, charlie_public_key)
bob_to_charlie_shared_secret = derive_shared_secret(bob_private_key, charlie_public_key)

# Guardar los secretos compartidos en archivos
with open("alice_to_bob_shared_secret.txt", "wb") as f:
    f.write(alice_to_bob_shared_secret)

with open("alice_to_charlie_shared_secret.txt", "wb") as f:
    f.write(alice_to_charlie_shared_secret)

with open("bob_to_charlie_shared_secret.txt", "wb") as f:
    f.write(bob_to_charlie_shared_secret)

print("¡Claves y secretos compartidos guardados en archivos!")
