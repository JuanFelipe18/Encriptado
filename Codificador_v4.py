from tkinter import simpledialog, filedialog, font
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from base64 import b64decode
from shutil import rmtree
from tkinter.ttk import *
from tkinter import *
import tkinter as tk
import numpy as np
import string
import random
import base64
import time
import sys
import cv2
import os
import io

class CodificadorGCM:
    def __init__(self):
        self.ventana_bienvenida = tk.Tk()
        self.ventana_bienvenida.title("Codificador GCM")
        self.imagen = tk.PhotoImage(file=self.resolver_ruta("logo.png"))  # Reemplaza con la ruta de tu imagen
        #self.imagen = tk.PhotoImage(file="logo.png")  # Reemplaza con la ruta de tu imagen
        self.imagen = self.imagen.subsample(6)  # Ajusta el factor de submuestreo según sea necesario
        self.fuente_personalizada = font.Font(family="Cambria Math", size=16)
        self.fuente_personalizada2 = font.Font(family="Sitka Subheading", size=16)
        self.setup_interfaz()

    def setup_interfaz(self):

        # Label para la imagen redimensionada
        label_imagen = tk.Label(self.ventana_bienvenida, image=self.imagen)
        label_imagen.pack()

        # Etiqueta de bienvenida con fuente y tamaño personalizados
        
        etiqueta_bienvenida = tk.Label(self.ventana_bienvenida, text="CODIFICADOR GCM", font=self.fuente_personalizada)
        etiqueta_bienvenida.pack(padx=10, pady=0)

        # Línea de texto adicional 1 con fuente y tamaño personalizados
        fuente_texto_adicional = font.Font(family="Courier New", size=12)
        texto_adicional_1 = tk.Label(self.ventana_bienvenida, text="Versión 1.5", font=fuente_texto_adicional)
        texto_adicional_1.pack()

        # Línea de texto adicional 2 con fuente y tamaño personalizados
        texto_adicional_2 = tk.Label(self.ventana_bienvenida, text="Grupo de Acceso a la Informacion y \nProtección de Datos Personales", font=fuente_texto_adicional)
        texto_adicional_2.pack()

        # Línea de texto adicional 3 con fuente y tamaño personalizados
        texto_adicional_3 = tk.Label(self.ventana_bienvenida, text="Autor: Juan Felipe Martín Martínez", font=fuente_texto_adicional)
        texto_adicional_3.pack()

        # Línea de texto adicional 4 con fuente y tamaño personalizados
        texto_adicional_4 = tk.Label(self.ventana_bienvenida, text="PROGRAMA DE USO EXCLUSIVO \nREGISTRADURIA NACIONAL DEL \nESTADO CIVIL", font=self.fuente_personalizada2)
        texto_adicional_4.pack()

        # Línea de texto adicional 5 con fuente y tamaño personalizados
        texto_adicional_5 = tk.Label(self.ventana_bienvenida, text="2023", font=fuente_texto_adicional)
        texto_adicional_5.pack()

        # Botón para iniciar la tarea
        self.boton_iniciar = tk.Button(self.ventana_bienvenida, text="Iniciar Codificación", command=self.iniciar_codificacion)
        self.boton_iniciar.pack(pady=20)

    def seleccionar_tipo(self):
        # Obtener la opción
        opcion1 = simpledialog.askinteger("Seleccionar", "Procesará Archivo o Imagen:                 \n\n1 ARCHIVO\n2 IMAGEN", minvalue=1, maxvalue=2)
        return opcion1

    def seleccionar_carpeta(self):
        opcion2 = simpledialog.askinteger("Seleccionar", "Elige una carpeta a procesar:                    \n\n1 APPL\n2 CAND\n3 TODOS", minvalue=1, maxvalue=3)
        return opcion2

    def seleccionar_extension(self):
        opcion3 = simpledialog.askinteger("Seleccionar", "Elige que tipo de archivo procesar:             \n\n1 ISO\n2 ANSI\n3 PKM\n4 TODOS", minvalue=1, maxvalue=4)
        return opcion3
    
    def seleccionar_si_encriptar(self):
        opcion4 = simpledialog.askinteger("Seleccionar", "Cifrar o Descrifrar:                                     \n\n1 CIFRAR\n2 DESCIFRAR\n3 AMBOS PROCESOS", minvalue=1, maxvalue=3)
        return opcion4

    def seleccionar_codificador(self):
        opcion5 = simpledialog.askinteger("Seleccionar", "Elige método para codificar:                     \n\n1 GCM\n2 CBC", minvalue=1, maxvalue=2)
        return opcion5

    def seleccionar_directorio(self):
        global directorio_principal
        directorio_seleccionado = filedialog.askdirectory()
        if directorio_seleccionado:
            directorio_principal = directorio_seleccionado

    def generar_clave(self, longitud):
        global archivo_clave
        os.chdir(directorio_principal)
        if os.path.exists(archivo_clave):
            os.remove(archivo_clave)
        caracteres = string.ascii_letters  # Esto incluye letras mayúsculas y minúsculas
        clave = ''.join(random.choice(caracteres) for _ in range(longitud))
        clave_byte = clave.encode('utf-8')
        with open(archivo_clave, "wb") as archivo_clave:
            archivo_clave.write(clave_byte)

    def cargar_clave(self, ruta):
        ruta_clave = os.path.join(ruta, "clave.key")
        with open(ruta_clave, "rb") as archivo_clave:
            return archivo_clave.read()

    def generar_nonce(self, longitud2):
        global archivo_nonce, archivo_nonceh

        os.chdir(directorio_principal)

        if os.path.exists(archivo_iv):
            os.remove(archivo_iv)
        if os.path.exists(archivo_ivh):
            os.remove(archivo_ivh)

        if os.path.exists(archivo_nonce):
            os.remove(archivo_nonce)
        if os.path.exists(archivo_nonceh):
            os.remove(archivo_nonceh) 
        
        if opcion5 == 2:
            archivo_nonce = "vector_ini_BASE64.iv"
            archivo_nonceh = "vector_ini_HEX.iv"

        caracteres = string.ascii_letters  # Esto incluye letras mayúsculas y minúsculas
        nonce = ''.join(random.choice(caracteres) for _ in range(longitud2))
        nonce_byte = nonce.encode('utf-8')
        with open(archivo_nonce, "wb") as archivo_nonce:
            archivo_nonce.write(nonce_byte)
        nonce_hex = nonce_byte.hex()
        with open(archivo_nonceh, "w") as archivo_nonceh:
            archivo_nonceh.write(nonce_hex)

    def cargar_nonce(self, ruta):
        if opcion5 == 2:    
            ruta_nonce = os.path.join(ruta, "vector_ini_BASE64.iv")
            with open(ruta_nonce, "rb") as archivo_nonce:
                return archivo_nonce.read()
        else:    
            ruta_nonce = os.path.join(ruta, "nonce_BASE64.nonce")
            with open(ruta_nonce, "rb") as archivo_nonce:
                return archivo_nonce.read()

    def procesar_archivosGCM(self, opcion3, opcion4, partes_porcentaje, total):
        for archivo in archivos:
            self.cantidad = self.cantidad + 1
            if (opcion3 == 1 or opcion3 == 4) and archivo.endswith('.iso-fmr'):
                nom_archivo = archivo
                if (opcion4 == 1 or opcion4 == 3):
                    self.encriptGCM(nom_archivo, clave, carpeta_muestrascif, nonce)
                if (opcion4 == 2 or opcion4 == 3):
                    self.desencriptGCM(nom_archivo, clave, carpeta_muestrasdes, nonce)

            if (opcion3 == 2 or opcion3 == 4) and archivo.endswith('.ansi-fmr'):
                nom_archivo = archivo
                if (opcion4 == 1 or opcion4 == 3):
                    self.encriptGCM(nom_archivo, clave, carpeta_muestrascif, nonce)
                if (opcion4 == 2 or opcion4 == 3):
                    self.desencriptGCM(nom_archivo, clave, carpeta_muestrasdes, nonce)

            if (opcion3 == 3 or opcion3 == 4) and archivo.endswith('.pkm'):
                nom_archivo = archivo
                if (opcion4 == 1 or opcion4 == 3):
                    self.encriptGCM(nom_archivo, clave, carpeta_muestrascif, nonce)
                if (opcion4 == 2 or opcion4 == 3):
                    self.desencriptGCM(nom_archivo, clave, carpeta_muestrasdes, nonce)
            self.calculo(partes_porcentaje, total, self.cantidad)

    def procesar_archivosCBC(self, opcion3, opcion4, partes_porcentaje, total):
        for archivo in archivos:
            self.cantidad = self.cantidad + 1
            if (opcion3 == 1 or opcion3 == 4) and archivo.endswith('.iso-fmr'):
                nom_archivo = archivo
                if (opcion4 == 1 or opcion4 == 3):
                    self.encriptGCM(nom_archivo, clave, carpeta_muestrascif, iv)
                if (opcion4 == 2 or opcion4 == 3):
                    self.desencriptGCM(nom_archivo, clave, carpeta_muestrasdes, iv)

            if (opcion3 == 2 or opcion3 == 4) and archivo.endswith('.ansi-fmr'):
                nom_archivo = archivo
                if (opcion4 == 1 or opcion4 == 3):
                    self.encriptGCM(nom_archivo, clave, carpeta_muestrascif, iv)
                if (opcion4 == 2 or opcion4 == 3):
                    self.desencriptGCM(nom_archivo, clave, carpeta_muestrasdes, iv)

            if (opcion3 == 3 or opcion3 == 4) and archivo.endswith('.pkm'):
                nom_archivo = archivo
                if (opcion4 == 1 or opcion4 == 3):
                    self.encriptGCM(nom_archivo, clave, carpeta_muestrascif, iv)
                if (opcion4 == 2 or opcion4 == 3):
                    self.desencriptGCM(nom_archivo, clave, carpeta_muestrasdes, iv)
            self.calculo(partes_porcentaje, total, self.cantidad)
                
    def encriptGCM(self, nom_archivo, clave, carpeta_muestrascif, nonce):
        os.chdir(muestras)
        with open(nom_archivo, "rb") as file:
            archivo_info = file.read()
        cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(archivo_info)
        nombre = os.path.basename(nom_archivo)
        ruta = os.path.join(carpeta_muestrascif, nombre)
        with open(ruta, "wb") as file:
            file.write(base64.b64encode(ciphertext))

    def desencriptGCM(self, nom_archivo, clave, carpeta_muestrasdes, nonce):
        os.chdir(carpeta_muestrascif)
        with open(nom_archivo, "rb") as file:
            encrypted_text = b64decode(file.read())
        cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)  
        decrypted_data = cipher.decrypt(encrypted_text)
        nombre = os.path.basename(nom_archivo)
        ruta = os.path.join(carpeta_muestrasdes,nombre)
        with open(ruta, "wb") as file:
            file.write(decrypted_data)

    def encriptImaG(self, nom_archivo, clave, carpeta_minuciascif, nonce):
        os.chdir(carpeta_minucias)
        with open(nom_archivo, 'rb') as file:
            image_bytes = file.read()

        cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(image_bytes)

        nombre = os.path.basename(nom_archivo)
        ruta = os.path.join(carpeta_minuciascif, nombre)
        with open(ruta, "wb") as file:
            file.write(ciphertext)

    def desencriptImaG(self, nom_archivo, clave, carpeta_minuciasdes, nonce):
        os.chdir(carpeta_minuciascif)
        with open(nom_archivo, "rb") as file:  # Abre el archivo .enc
            encrypted_text = file.read()

        cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt(encrypted_text)

        # Utilizar un buffer para reconstruir la imagen
        img_buffer = io.BytesIO(decrypted_data)
        decrypted_image = cv2.imdecode(np.frombuffer(img_buffer.read(), np.uint8), cv2.IMREAD_COLOR)
        ruta = os.path.join(carpeta_minuciasdes, nom_archivo)
        cv2.imwrite(ruta, decrypted_image)

    def encriptCBC(self, nom_archivo, clave, carpeta_muestrascif, iv):
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

    def desencriptCBC(self, nom_archivo, clave, carpeta_muestrasdes, iv):
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

    def encriptImaC(self, nom_archivo, clave, carpeta_minuciascif, iv):
        global height, width, channels
        os.chdir(carpeta_minucias)
        image = cv2.imread(nom_archivo)
        height, width, channels = image.shape
        image_bytes = image.tobytes()
        cipher = AES.new(clave, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(pad(image_bytes, AES.block_size, style='pkcs7'))
        nombre = os.path.basename(nom_archivo)
        ruta = os.path.join(carpeta_minuciascif, nombre + ".enc")  # Cambia la extensión a ".enc"
        with open(ruta, "wb") as file:
            file.write(encrypted_text)

    def desencriptImaC(self, nom_archivo, clave, carpeta_minuciasdes, iv):
        os.chdir(carpeta_minuciascif)
        ruta_encrypted = nom_archivo
        with open(ruta_encrypted, "rb") as file:  # Abre el archivo .enc
            encrypted_data = file.read()
        cipher = AES.new(clave, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size, style='pkcs7')
        ruta = os.path.join(carpeta_minuciasdes, nom_archivo)
        cv2.imwrite(ruta, np.frombuffer(decrypted_data, dtype=np.uint8).reshape(height, width, channels))

    def resolver_ruta(self, archivo):
        if hasattr(sys, '_MEIPASS'):  # Verifica si estamos en el entorno empaquetado
            return os.path.join(sys._MEIPASS, archivo)
        else:
            return os.path.join(os.path.abspath('.'), archivo)

    def progress_bar(self):
        self.ventana_progreso = tk.Toplevel()
        self.ventana_progreso.title("ProgressBar")
        self.ventana_progreso.geometry("300x100")

        self.progressbar = tk.Canvas(self.ventana_progreso, width=280, height=20, bg='white')
        self.progressbar.place(x=10, y=40)

        self.percent = tk.StringVar()
        self.text = tk.StringVar()

        self.percent_label = tk.Label(self.ventana_progreso, textvariable=self.percent, font=("Arial", 10))
        self.percent_label.place(x=180, y=10)

        self.text_label = tk.Label(self.ventana_progreso, textvariable=self.text, font=("Arial", 10))
        self.text_label.place(x=60, y=65)

        self.progressbar_bar = self.progressbar.create_rectangle(0, 0, 0, 20, fill='blue')

        self.label = tk.Label(self.ventana_progreso, text="Procesando", font=("Arial", 10))
        self.label.place(x=100, y=10)

        self.ventana_progreso.update()  # Actualiza la ventana gráfica

    def progreso(self, porcentaje, total, cantidad):
        self.percent.set(str(porcentaje) + "%")
        self.text.set(str(cantidad) + "/" + str(total) + " archivos completados")
        self.progressbar.coords(self.progressbar_bar, 0, 0, porcentaje * 2.8, 20)
        self.ventana_progreso.update_idletasks()  # Actualiza la ventana gráfica

    def calculo(self,partes_porcentaje, total, cantidad):
        if partes_porcentaje >= 1:
            if cantidad % partes_porcentaje == 0:
                porcentaje = int((cantidad / total) * 100)
                self.progreso(porcentaje, cantidad, total)
        else:
            porcentaje = int((cantidad / total) * 100)
            self.progreso(porcentaje, cantidad, total)

    def iniciar_codificacion(self):
        self.ventana_bienvenida.withdraw()  # Oculta la ventana de bienvenida
        self.main()  # Iniciar la lógica principal

    def main(self):
        global carpeta_minuciascif, carpeta_minuciasdes,carpeta_minucias
        global archivos, muestras, iv, clave, nonce, inicio_tiempo, n
        global opcion1, opcion2, opcion3, opcion4, opcion5, porcentaje
        global carpeta_muestrascif, carpeta_muestrasdes, general
    
        
        self.cantidad = 0

        # SELECCIONAR DIRECTORIO PRINCIPAL
        self.seleccionar_directorio()
        
        # ARCHIVO O IMAGEN
        opcion1 = self.seleccionar_tipo()

        # ELIGE CARPETA A PROCESAR
        if opcion1 == 1:
            opcion2 = self.seleccionar_carpeta()
            # ELEGIR EXTENSION
            opcion3 = self.seleccionar_extension()
            if opcion2 == 3:
                general = 2

        # ENCRIPTA O DESENCRIPTA
        opcion4 = self.seleccionar_si_encriptar()

        # MODO DE ENCRIPTACION
        opcion5 = self.seleccionar_codificador()

        # DIRECTORIO BASE
        directorio_cifrado = os.path.join(directorio_principal,"cifrado")
        directorio_descifrado = os.path.join(directorio_principal,"descifrado")

        # LIMPIEZA Y CREACION DIRECTORIOS
        if (os.path.exists(directorio_cifrado) and opcion4 != 2):
            rmtree(directorio_cifrado)
        if os.path.exists(directorio_descifrado):
            rmtree(directorio_descifrado)

        # CREA DIRECTORIOS CIFRADO
        if (opcion4 == 1 or opcion4 == 3):
            os.makedirs(os.path.join(directorio_principal,"cifrado"))
        if (opcion4 == 2 or opcion4 == 3):
            os.makedirs(os.path.join(directorio_principal,"descifrado"))

        # GENERA CLAVE
        if opcion4 != 2:
            self.generar_clave(32)
        clave = self.cargar_clave(directorio_principal)

        # GENERA NONCE BASE64
        if (opcion4 != 2):
            self.generar_nonce(16)
        if (opcion5 == 1): # GCM
            nonce = self.cargar_nonce(directorio_principal)
        if (opcion5 == 2): # CBC
            iv = self.cargar_nonce(directorio_principal)

        # CICLO PRINCIPAL
        applcand = [entrada.name for entrada in os.scandir(directorio_principal) if entrada.is_dir()]

        inicio_tiempo = time.time()

        self.progress_bar()
        
        if opcion1 == 1:   
            for carpeta in applcand:
                if carpeta.lower() not in ["appl", "cand"]:
                    continue

                if opcion2 == 1 and carpeta.lower() not in ["appl"]:
                    continue

                if opcion2 == 2 and carpeta.lower() not in ["cand"]:
                    continue
                
                if (opcion4 == 1 or opcion4 == 3):
                    carpeta_minuciascif = os.path.join(directorio_cifrado, str(carpeta))
                    os.makedirs(carpeta_minuciascif)
                if (opcion4 == 2 or opcion4 == 3):
                    carpeta_minuciasdes = os.path.join(directorio_descifrado, str(carpeta))
                    carpeta_minuciascif = os.path.join(directorio_cifrado, str(carpeta))
                    os.makedirs(carpeta_minuciasdes)
                carpeta_minucias = os.path.join(directorio_principal, carpeta)

                carp = [entrada.name for entrada in os.scandir(carpeta_minucias) if entrada.is_dir()]

                for subcarpeta in carp:
                    muestras = os.path.join(carpeta_minucias, subcarpeta)
                    if (opcion4 == 1 or opcion4 == 3):
                        os.makedirs(os.path.join(carpeta_minuciascif, str(subcarpeta)))
                        carpeta_muestrascif = os.path.join(carpeta_minuciascif, str(subcarpeta))
                    if (opcion4 == 2 or opcion4 == 3):
                        os.makedirs(os.path.join(carpeta_minuciasdes, str(subcarpeta)))
                        carpeta_muestrascif = os.path.join(carpeta_minuciascif, str(subcarpeta))
                        carpeta_muestrasdes = os.path.join(carpeta_minuciasdes, str(subcarpeta))

                    archivos = os.listdir(muestras)
                    total = len(archivos)*len(carp)*general
                    partes_porcentaje = total / 100 if total > 0 else 1
                    if opcion5 == 1:
                        self.procesar_archivosGCM(opcion3, opcion4, partes_porcentaje, total)
                    if opcion5 == 2:
                        self.procesar_archivosCBC(opcion3, opcion4, partes_porcentaje, total)
                os.chdir(directorio_principal)
        
        if opcion1 == 2:
            for carpeta in applcand:
                if carpeta.lower() not in ["img"]:
                    continue
                
                if (opcion4 == 1 or opcion4 == 3):
                    carpeta_minuciascif = os.path.join(directorio_cifrado, str(carpeta))
                    os.makedirs(carpeta_minuciascif)
                if (opcion4 == 2 or opcion4 == 3):
                    carpeta_minuciasdes = os.path.join(directorio_descifrado, str(carpeta))
                    carpeta_minuciascif = os.path.join(directorio_cifrado, str(carpeta))
                    os.makedirs(carpeta_minuciasdes)
                carpeta_minucias = os.path.join(directorio_principal, carpeta)

                archivos = os.listdir(carpeta_minucias)
                total = len(archivos)
                partes_porcentaje = total / 100 if total > 0 else 1

                if opcion5 == 1:
                    for archivo in archivos:
                        self.cantidad += 1
                        nom_archivo = archivo
                        if (opcion4 == 1 or opcion4 == 3):
                            self.encriptImaG(nom_archivo, clave, carpeta_minuciascif, nonce)
                        if (opcion4 == 2 or opcion4 == 3):
                            self.desencriptImaG(nom_archivo, clave, carpeta_minuciasdes, nonce)
                        self.calculo(partes_porcentaje, total, self.cantidad)

                if opcion5 == 2:
                    for archivo in archivos:
                        self.cantidad += 1
                        nom_archivo = archivo
                        if (opcion4 == 1 or opcion4 == 3):
                            self.encriptImaG(nom_archivo, clave, carpeta_minuciascif, iv)
                        if (opcion4 == 2 or opcion4 == 3):
                            self.desencriptImaG(nom_archivo, clave, carpeta_minuciasdes, iv)
                        self.calculo(partes_porcentaje, total, self.cantidad)
                    
                os.chdir(directorio_principal)

        self.mostrar_ventana_final()

    def mostrar_ventana_final(self):
        fin_tiempo = time.time()
        tiempo_transcurrido = fin_tiempo - inicio_tiempo
        with open("Tiempo.txt", "w") as archivo_tiempo:
            archivo_tiempo.write(str(tiempo_transcurrido))
        ventana_final = tk.Toplevel()
        ventana_final.title("Finalizo")

        label_imagen = tk.Label(ventana_final, image=self.imagen)
        label_imagen.pack()

        etiqueta_final = tk.Label(ventana_final, text="¡Proceso finalizado con éxito!", font=self.fuente_personalizada)
        etiqueta_final.pack(padx=10, pady=5)

        boton_aceptar = tk.Button(ventana_final, text="Aceptar", command=self.cerrar_programa)
        boton_aceptar.pack(pady=5)

        ventana_final.protocol("WM_DELETE_WINDOW", self.cerrar_programa)  # Manejar el cierre de la ventana

    def cerrar_programa(self):
        self.ventana_bienvenida.quit()  # Salir del bucle de la interfaz gráfica

# VARIABLES
n = 0
general = 1
porcentaje = 0
fin_tiempo = 0
inicio_tiempo = 0
archivo_nonce = "nonce_BASE64.nonce"
archivo_nonceh = "nonce_HEX.nonce"
archivo_iv = "vector_ini_BASE64.iv"
archivo_ivh = "vector_ini_HEX.iv"
archivo_clave = "clave.key"
directorio_principal = None
if __name__ == "__main__":
    app = CodificadorGCM()
    app.ventana_bienvenida.mainloop()  # Iniciar el bucle de la interfaz gráfica
