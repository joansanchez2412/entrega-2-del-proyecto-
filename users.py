# Estos son los paquetes que se deben instalar
# pip install pycryptodome
# pip install pyqrcode
# pip install pypng
# pip install pyzbar
# pip install pillow

# No modificar estos módulos que se importan
from optparse import Values
from pyzbar.pyzbar import decode
from PIL import Image
from json import dumps
from json import loads
from hashlib import sha256
from Crypto.Cipher import AES
import base64
import pyqrcode
from os import urandom
import io
from datetime import datetime
import cv2
import numpy as np
import time
import json
from os.path import exists

KEYS_FILE = "keys.json"

def load_keys():
    if exists(KEYS_FILE):
        with open(KEYS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f)

def get_key_for_today():
    today = datetime.today().strftime('%Y-%m-%d')
    keys = load_keys()
    if today not in keys:
        new_key = base64.b64encode(urandom(32)).decode('ascii')
        keys[today] = new_key
        save_keys(keys)
    return base64.b64decode(keys[today]), today

def get_key_for_date(date_str):
    keys = load_keys()
    if date_str in keys:
        return base64.b64decode(keys[date_str])
    return None

# Nombre del archivo con la base de datos de usuarios
usersFileName = "users.txt"

# Fecha actual
date = None
# Clave aleatoria para encriptar el texto de los códigos QR
key = None

# Función para encriptar (no modificar)
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

# Función para desencriptar (no modificar)
def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# Función que genera un código QR (no modificar)
def generateQR(id, program, role, buffer):
    data = {'id': id, 'program': program, 'role': role}
    datas = dumps(data).encode("utf-8")

    key, today = get_key_for_today()
    encrypted = list(encrypt_AES_GCM(datas, key))

    qr_text = dumps({
        'qr_text0': base64.b64encode(encrypted[0]).decode('ascii'),
        'qr_text1': base64.b64encode(encrypted[1]).decode('ascii'),
        'qr_text2': base64.b64encode(encrypted[2]).decode('ascii'),
        'date': today
    })

    qrcode = pyqrcode.create(qr_text)
    qrcode.png(buffer, scale=8)

# Clases para roles de usuarios
class Usuario:
    def __init__(self, id, program, role):
        self.id = id
        self.program = program
        self.role = role

class Profesor(Usuario):
    def __init__(self, id, program):
        super().__init__(id, program, "profesor")

class Estudiante(Usuario):
    def __init__(self, id, program):
        super().__init__(id, program, "estudiante")

# Clase encargada de detectar espacios disponibles en el parqueadero
def definir_espacios(frame):
    alto = frame.shape[0]
    ancho = frame.shape[1]

    espacios = []
    filas = 2
    columnas = 5
    ancho_rect = ancho // columnas
    alto_rect = alto // 3

    margen_horizontal = 5  # antes 10
    margen_rect_horizontal = 10  # antes 20
    margen_vertical = 30  # antes 40

    for fila in range(filas):
        y = margen_vertical if fila == 0 else alto - alto_rect - margen_vertical
        for col in range(columnas):
            x = col * ancho_rect + margen_horizontal
            espacios.append((x, y, x + ancho_rect - margen_rect_horizontal, y + alto_rect))
    return espacios

def identifySpot(frame):
    espacios = definir_espacios(frame)
    escala_de_Grises = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    borde = cv2.Canny(escala_de_Grises, 50, 100)

    libres_profesores = []
    libres_estudiantes = []

    for i, (x1, y1, x2, y2) in enumerate(espacios):
        region = borde[y1:y2, x1:x2]
        numero_borde = np.count_nonzero(region == 255)
        libre = numero_borde < 2000

        if i < 5 and libre:
            libres_profesores.append(i + 1)
        elif i >= 5 and libre:
            libres_estudiantes.append(i + 1)

    return libres_profesores, libres_estudiantes

# Se debe codificar esta función
def registerUser(id, password, program, role):
    try:
        with open(usersFileName, "a+") as U:
            U.seek(0)
            for linea in U:
                if linea.strip():
                    usuario = loads(linea.strip())
                    if usuario["id"] == id:
                        return "User already registered"

            hashed_password = sha256(password.encode()).hexdigest()
            n_usuario = {
                "id": id,
                "password": hashed_password,
                "program": program,
                "role": role
            }
            U.write(dumps(n_usuario) + "\n")
            return "User successfully registered"
    except:
        return "Error registering user"

# Función que genera el código QR
def getQR(id, password):
    buffer = io.BytesIO()
    hashed_password = sha256(password.encode()).hexdigest()

    try:
        with open(usersFileName, "r") as U:
            for linea in U:
                if linea.strip():
                    usuario = loads(linea.strip())
                    if usuario["id"] == id and usuario["password"] == hashed_password:
                        generateQR(id, usuario["program"], usuario["role"], buffer)
                        return buffer
    except:
        return None

# Función que recibe el código QR como PNG
def sendQR(png):
    try:
        # Decodificar QR
        decoded_objs = decode(Image.open(io.BytesIO(png)))
        if not decoded_objs:
            return "QR no válido o no se pudo leer"

        try:
            decodedQR = decoded_objs[0].data.decode('ascii')
            data = loads(decodedQR)
        except Exception as e:
            return f"QR inválido o malformado: {e}"

        # Leer la fecha del QR y obtener la clave correspondiente
        fecha_qr = data.get("date")
        key_qr = get_key_for_date(fecha_qr)
        if not key_qr:
            return "Clave no disponible para la fecha del QR"

        decrypted = loads(decrypt_AES_GCM(
            (
                base64.b64decode(data["qr_text0"]),
                base64.b64decode(data["qr_text1"]),
                base64.b64decode(data["qr_text2"])
            ), key_qr))

        user_id = decrypted["id"]
        role = decrypted["role"]
        program = decrypted["program"]

        # Buscar usuario en archivo
        with open(usersFileName, "r") as U:
            usuarios = [loads(line.strip()) for line in U if line.strip()]
        
        usuario = next((u for u in usuarios if u["id"] == user_id), None)
        if not usuario:
            return "Usuario no registrado"

        # Crear objeto de usuario
        user_obj = Profesor(user_id, program) if role == "profesor" else Estudiante(user_id, program)

        # Captura de cámara
        cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        time.sleep(1)
        ret, frame = cam.read()
        cam.release()

        if not ret:
            return "Error capturando imagen del parqueadero"

        espacios = definir_espacios(frame)
        escala_de_Grises = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        borde = cv2.Canny(escala_de_Grises, 50, 100)

        libres_profesores = []
        libres_estudiantes = []
        estado_espacios = []

        for i, (x1, y1, x2, y2) in enumerate(espacios):
            region = borde[y1:y2, x1:x2]
            numero_borde = np.count_nonzero(region == 255)
            libre = numero_borde < 2000
            estado = "libre" if libre else "ocupada"
            estado_espacios.append(estado)

            if i < 5 and libre:
                libres_profesores.append(i + 1)
            elif i >= 5 and libre:
                libres_estudiantes.append(i + 1)

        estado_texto = "; ".join([f"Plaza {i+1}: {estado_espacios[i]}" for i in range(len(estado_espacios))])
        print(f"Estado plazas detectadas: {estado_texto}")

        if role == "profesor" and libres_profesores:
            return f"Puesto asignado: {libres_profesores[0]}"
        elif role == "estudiante" and libres_estudiantes:
            return f"Puesto asignado: {libres_estudiantes[0]}"
        else:
            return "No hay puestos disponibles para su rol"

    except Exception as e:
        return f"Código QR inválido o clave expirada: {str(e)}"

def mostrar_camara_en_vivo():
    cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    if not cam.isOpened():
        print("No se pudo abrir la cámara.")
        return

    print("Presiona 'q' para salir...")
    while True:
        ret, frame = cam.read()
        if not ret:
            print("No se pudo leer el frame.")
            break

        espacios = definir_espacios(frame)
        libres_profesores, libres_estudiantes = identifySpot(frame)

        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        display_frame = cv2.cvtColor(gray_frame, cv2.COLOR_GRAY2BGR)

        for i, (x1, y1, x2, y2) in enumerate(espacios):
            if i < 5:
                estado = "libre" if (i + 1) in libres_profesores else "ocupada"
            else:
                estado = "libre" if (i + 1) in libres_estudiantes else "ocupada"

            color = (0, 255, 0) if estado == "libre" else (0, 0, 255)
            cv2.rectangle(display_frame, (x1, y1), (x2, y2), color, 2)

        cv2.imshow("Vista en Vivo - Parqueadero", display_frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cam.release()
    cv2.destroyAllWindows()

mostrar_camara_en_vivo()