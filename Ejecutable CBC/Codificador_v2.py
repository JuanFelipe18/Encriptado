# PAGINAS WEB PARA PROBAR:
# https://www.javainuse.com/aesgenerator
# https://www.devglan.com/online-tools/aes-encryption-decryption
# https://the-x.cn/en-US/cryptography/Aes.aspx
# https://encode-decode.com/aes-256-cbc-encrypt-online/

from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from tkinter import Tk, filedialog
from tkinter import simpledialog
from Crypto.Cipher import AES
from shutil import rmtree
import secrets
import base64
import random
import string
import glob
import os

# DIALOGO DE SELECCION OPCION
def seleccionar_opcion():
    opcion = simpledialog.askinteger("Seleccionar Opción", "Elige una opción:\n1 ISO\n2 ANSI\n3 PKM\n4 TODOS\n5 FINALIZAR", minvalue=1, maxvalue=5)
    return opcion

# SELECCION DIRECTORIO
def seleccionar_directorio():
    global directorio_principal
    directorio_seleccionado = filedialog.askdirectory()
    if directorio_seleccionado:
        directorio_principal = directorio_seleccionado

# PROCESAR ARCHIVOS
def procesar_archivos(opcion):
    for archivo in archivos:
        if (opcion == 1 or opcion == 4) and archivo.endswith('.iso-fmr'):
            nom_archivo = archivo
            encript(nom_archivo, clave, carpeta_muestrascif)
            desencript(nom_archivo, clave, carpeta_muestrasdes)
        if (opcion == 2 or opcion == 4) and archivo.endswith('.ansi-fmr'):
            nom_archivo = archivo
            encript(nom_archivo, clave, carpeta_muestrascif)
            desencript(nom_archivo, clave, carpeta_muestrasdes)
        if (opcion == 3 or opcion == 4) and archivo.endswith('.pkm'):
            nom_archivo = archivo
            encript(nom_archivo, clave, carpeta_muestrascif)
            desencript(nom_archivo, clave, carpeta_muestrasdes)

# GENERAR CLAVE
def generar_clave(longitud):
    global archivo_clave
    os.chdir(directorio_principal)
    if os.path.exists(archivo_clave):
        os.remove(archivo_clave)
    caracteres = string.ascii_letters  # Esto incluye letras mayúsculas y minúsculas
    clave = ''.join(random.choice(caracteres) for _ in range(longitud))
    clave_byte = clave.encode('utf-8')
    with open(archivo_clave, "wb") as archivo_clave:
        archivo_clave.write(clave_byte)

# CARGAR .KEY
def cargar_clave(ruta):
    ruta_clave = os.path.join(ruta, "clave.key")
    with open(ruta_clave, "rb") as archivo_clave:
        return archivo_clave.read()

# GENERA EL IV BASE64
def generar_iv(longitud2):
    global archivo_iv, archivo_ivh
    os.chdir(directorio_principal)
    if os.path.exists(archivo_iv):
        os.remove(archivo_iv)
    caracteres = string.ascii_letters  # Esto incluye letras mayúsculas y minúsculas
    iv = ''.join(random.choice(caracteres) for _ in range(longitud2))
    iv_byte = iv.encode('utf-8')
    with open(archivo_iv, "wb") as archivo_iv:
        archivo_iv.write(iv_byte)
    iv_hex = iv_byte.hex()
    with open(archivo_ivh, "w") as archivo_ivh:
        archivo_ivh.write(iv_hex)

# CARGAR IV BASE64
def cargar_iv(ruta):
    ruta_iv = os.path.join(ruta, "vector_ini_ASCII.iv")
    with open(ruta_iv, "rb") as archivo_iv:
        return archivo_iv.read()

#ENCRIPTA LOS ARCHIVOS
def encript(nom_archivo, clave, carpeta_muestrascif):
    os.chdir(muestras)
    with open(nom_archivo, "rb") as file:
        archivo_info = file.read()
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    encrypted_text = cipher.encrypt(pad(archivo_info, AES.block_size, style='pkcs7'))
    nombre = os.path.basename(nom_archivo)
    ruta = os.path.join(carpeta_muestrascif, nombre)
    with open(ruta, "wb") as file:
        result = b64encode(iv + encrypted_text)
        file.write(result)

def desencript(nom_archivo,clave, carpeta_muestrasdes):
    os.chdir(carpeta_muestrascif)
    with open(nom_archivo, "rb") as file:
        encrypted_data = file.read()
    encrypted_text = b64decode(encrypted_data)
    ciphertext = encrypted_text[16:]  # Extract the encrypted text
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size, style='pkcs7')
    nombre = os.path.basename(nom_archivo)
    ruta = os.path.join(carpeta_muestrasdes,nombre)
    with open(ruta, "wb") as file:
        file.write(decrypted_data)

# VARIABLES
opcion = 0
archivo_iv = "vector_ini_ASCII.iv"
archivo_ivh = "vectorh_ini_HEX.iv"
archivo_clave = "clave.key"
directorio_principal = None

# VENTANA Tkinter PARA SELECCION DIRECTORIO
ventana = Tk()
ventana.withdraw()  # Ocultar la ventana principal

# SELECCIONAR DIRECTORIO PRINCIPAL
seleccionar_directorio()

# DIRECTORIO BASE
directorio_cifrado = os.path.join(directorio_principal,"Cifrado")
directorio_descifrado = os.path.join(directorio_principal,"Descifrado")

# LIMPIEZA Y CREACION DIRECTORIOS
if os.path.exists(directorio_cifrado):
    rmtree(directorio_cifrado)
if os.path.exists(directorio_descifrado):
    rmtree(directorio_descifrado)
os.makedirs(os.path.join(directorio_principal,"Descifrado"))
os.makedirs(os.path.join(directorio_principal,"Cifrado"))

# GENERA CLAVE
generar_clave(32)
clave = cargar_clave(directorio_principal)

# GENERA IV ASCII
generar_iv(16)
iv = cargar_iv(directorio_principal)

# ELEGIR EXTENSION
opcion = seleccionar_opcion()

# CICLO PRINCIPAL
applcand = [entrada.name for entrada in os.scandir(directorio_principal) if entrada.is_dir()]
for carpeta in applcand:
    if carpeta != "Appl" and carpeta != "Cand":
        continue
    carpeta_minuciascif = os.path.join(directorio_cifrado, str(carpeta))
    carpeta_minuciasdes = os.path.join(directorio_descifrado, str(carpeta))
    os.makedirs(carpeta_minuciascif)
    os.makedirs(carpeta_minuciasdes)
    carpeta_minucias = os.path.join(directorio_principal, carpeta)

    carp = [entrada.name for entrada in os.scandir(carpeta_minucias) if entrada.is_dir()]

    for subcarpeta in carp:
        muestras = os.path.join(carpeta_minucias, subcarpeta)

        os.makedirs(os.path.join(carpeta_minuciascif, str(subcarpeta)))
        os.makedirs(os.path.join(carpeta_minuciasdes, str(subcarpeta)))
        carpeta_muestrascif = os.path.join(carpeta_minuciascif, str(subcarpeta))
        carpeta_muestrasdes = os.path.join(carpeta_minuciasdes, str(subcarpeta))

        archivos = os.listdir(muestras)
        procesar_archivos(opcion)

    os.chdir(directorio_principal)