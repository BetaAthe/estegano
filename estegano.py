import os
import hashlib
import argparse
import zipfile
from io import BytesIO
import numpy as np # numpy
import imageio # imageio
from rfc7539 import aead as chacha #rfc7539


### ESTRUCTURA ###

# Convierte un fichero/carpeta a una estructura
def fileToStruct(name: str) -> bytes:
	# ZIP
	buff = BytesIO()
	zf = zipfile.ZipFile(buff, mode="w", compression=zipfile.ZIP_DEFLATED)
	if os.path.isdir(name):
		for root, dirs, files in os.walk(name):
			for file in files:
				zf.write(os.path.join(root, file))
	else:
		with open(name, "rb") as f:
			zf.writestr(name, f.read())
	zf.close()
	zdata = buff.getvalue()
	
	# SIZE: variable bytes indicando bytes del fichero
	size = len(zdata)
	out=0
	for i in range(size.bit_length()//8+1):
		out <<= 1  # Hueco para primer bit
		out |= size.bit_length()>7 # 1 se sigue, 0 ultimo byte
		out <<= 7  # Hueco para los 7 bits de datos
		out |= size & 0b01111111 # Coger los 7 bits de datos
		size >>= 7 # Descartar del dato original los 7 bits menos significativos

	# DATA
	return bytes( out.to_bytes((out.bit_length()+7)//8,'big') + zdata )


# Convierte una estructura a un binario 
def structToFile(data: bytes, name: str) -> None:
	# SIZE
	size = 0
	byte_size = 0
	while True:
		size = size | ((data[byte_size] & 0b01111111)<<(7*byte_size))
		byte_size+=1
		if data[byte_size-1] & 0b10000000==0:
			break

	# DATA
	filebytes = BytesIO(data[byte_size:byte_size+size])
	with zipfile.ZipFile(filebytes) as zip_ref:
		zip_ref.extractall(name)
	


### CIFRADO ###

# Añade una capa de cifrado con chacha20 y poly1305 (+ruido extra)
# Data: datos, size: tamaño del canal, pwd: contraseña
def addCipherLayer(data: bytes, size: int, pwd: str=None) -> bytes:
	key = hashlib.sha256(pwd.encode()).digest() if pwd!=None else os.urandom(32)
	nonce = os.urandom(12)
	tam = size-len(data)-12-16-(0 if pwd!=None else 32)
	result,mac = chacha.encrypt_and_tag(key, nonce, data+os.urandom(tam), b"estegano")
	return nonce + result + mac if pwd!=None else key + nonce + result + mac


# Elimina una capa de cifrado de un bytearray
def removeCipherLayer(data: bytes, pwd: str=None) -> bytes:
	key = hashlib.sha256(pwd.encode()).digest() if pwd!=None else data[0:32]
	index_nonce = 0 if pwd!=None else 32
	index_data = index_nonce + 12
	return chacha.verify_and_decrypt(key, data[index_nonce:index_data],data[index_data:len(data)-16],data[len(data)-16:], b"estegano")



### INYECCIÓN ###

# Inyecta datos en la imagen
# imagen, mascara base, datos, n espacio separacion
def inyectData(image: np.ndarray, mask: np.ndarray, data: bytes, n: int) -> np.ndarray:
	#Aplanar
	forma = image.shape
	image=image.flatten()
	mask=mask.flatten()
	
	# Mover bytes a 254 -> 255
	image[image==254]=255 
	
	# Inyectar byte n
	imm = image[mask][:8]
	x=np.unpackbits(bytearray((n-1).to_bytes(1,'big')))
	imm += np.bitwise_xor( x, np.bitwise_and(imm, 1))
	image[np.where(mask)[0][:8]]=imm
	
	# Vista para inyectar el resto de bits
	imm = image[mask][8+n-1::n]

	# Añadir rand byte para bits extra y desempaquetar
	dataunp = np.unpackbits( np.frombuffer(data + os.urandom(1), dtype=np.uint8) )
	dataunp = dataunp[:imm.size-dataunp.size] #eliminar bits sobrantes

	# Inyectar
	imm += np.bitwise_xor(dataunp, np.bitwise_and(imm, 1)) #(bitdata xor imm&1) + imm
	image[np.where(mask)[0][8+n-1::n]]=imm
		
	return image.reshape(forma)


# Recupera datos de una imagen
def retrieveData(image: np.ndarray) -> bytes:
	mask=(image > 1) & (image < 255)
	n = int.from_bytes( np.packbits(np.bitwise_and(image[mask][0:8], 1) ), 'big')
	channel = image[mask][8+n::n+1]
	return bytes(np.packbits( np.bitwise_and(channel, 1) )[:(-1 if len(channel) % 8 != 0 else len(channel))])



### LÓGICA ###

# Ocultar datos
def hide(inputf: str, hide: str, outputf: str, passwd: str) -> None:

	if not os.path.exists(inputf) or not os.path.exists(hide):
		print("[Error] No se encuentra: "+hide)
		exit()

	# Leer imagen contenedora
	img = np.asarray(imageio.imread(inputf))
	logInfo("Se ha leído correctamente la imagen contenedora.")

	#Generar estructura
	estruct = fileToStruct(hide)
	logInfo("El tamaño de la estructura de datos es de "+str(len(estruct)*8)+" bits.")

	# Generar máscara y obtener bits inyectables
	usable_mask = (img > 1) & (img < 254)
	usable = np.count_nonzero(usable_mask)-8 #-1 byte dedicado al valor n
	logInfo("La imagen contiene un total de "+str(usable)+" bits inyectables de un total de "+str(img.size)+".")

	# Obtener n, el número de estructuras que caben en la imagen
	# util/tamaño: 12 bytes de nonce, 16 bytes de tag, [32 bytes de pass]
	n = usable//((len(estruct)+12+16+(0 if passwd!=None else 32))*8)
	n=min(n,256) # max 256 de tamaño
	canal_bytes = usable//n//8

	if n==0:
		print("[Error] La imagen es demasiado pequeña o los datos son demasiado grandes como para poder ocultarlos.")
		exit()

	logInfo("La imagen y los datos cuentan con un valor n = "+str(n)+".")
	logInfo("El tamaño del canal es de "+str(canal_bytes*8)+" bits.")

	if n<12:
		print("[Atención] Podría llegar a detectarse que existen datos ocultos en la imagen debido a que el ratio (capacidad de imagen:datos) es de solo "+str(n)+":1. Se recomienda usar una imagen más grande u ocultar datos más pequeños.")

	# Cifrar
	data = addCipherLayer(estruct, canal_bytes, passwd)
	logInfo("Datos cifrados correctamente con una contraseña "+("aleatoria." if passwd == None else "definida por el usuario."))

	# Inyectar en la imagen, con una máscara, unos datos por el canal n
	res = inyectData(img, usable_mask, data, n)

	# Guardar imagen
	salida = outputf if outputf != None else inputf
	imageio.imwrite(salida, res)
	if outputf != None:
		print("[Atención] Se ha creado una nueva imagen conteniendo los datos ocultos. Se recomienda deshacerse de la imagen original.")
	
	if salida[-3:] not in ("png","bmp"):
		print("[Atención] No se soporta el uso de imagenes de salida que no sean .png o .bmp. Si se continúa, podrían darse pérdidas de datos.")

	logInfo("Se han inyectado los datos en la imagen con éxito.")


# Deocultar datos
def unhide(inputf: str, outputf: str, passwd: str) -> None:

	if not os.path.exists(inputf):
		print("[Error] No se encuentra: "+file_hide)
		exit()

	# Leer imagen contenedora
	img = np.asarray(imageio.imread(inputf))
	logInfo("Se ha leído correctamente la imagen contenedora.")

	# Obtener bloque de bytes
	data = retrieveData(img)
	logInfo("Se han extraído "+str(len(data)*8)+" bits en bruto.")

	# Descifrar
	try:
		descifrado = removeCipherLayer(data, passwd)
		logInfo("Se han descifrado los datos correctamente.")
	except:
		print("[Error] No se pueden obtener los datos ocultos. Puede que:")
		print("1. Esta imagen no oculta ningún archivo.")
		print("2. Se han corrompido los datos ocultos.")
		exit()

	# Obtener resultado
	resultado = structToFile(descifrado, outputf if outputf != None else ".")
	logInfo("Se han recuperado los datos ocultos de la imagen correctamente.")


# Limpiar imágenes
def clean(inputf: str, outputf: str) -> None:
	if not os.path.exists(inputf):
		print("[Error] No se encuentra: "+file_hide)
		exit()

	image = np.asarray(imageio.imread(inputf))
	logInfo("Se ha leído correctamente la imagen contenedora.")

	forma = image.shape
	image=image.flatten()

	# Obtener n
	mask=(image > 1) & (image < 255)
	n = int.from_bytes( np.packbits(np.bitwise_and(image[mask][0:8], 1) ), 'big')

	# n aleatorio
	imm = image[mask][:8]
	imm = np.left_shift(np.right_shift(imm,1),1) #0 en el lsb
	imm += np.unpackbits(bytearray(os.urandom(1)))
	image[np.where(mask)[0][:8]]=imm
	
	# Copiar 2LSB a LSB
	imm = image[mask][8+n::n+1]
	imm = np.left_shift(np.right_shift(imm,1),1) #0 en el lsb
	imm += np.right_shift( np.bitwise_and(imm, 0b10),1)
	image[np.where(mask)[0][8+n::n+1]]=imm

	image = image.reshape(forma)
	salida = outputf if outputf != None else inputf
	imageio.imwrite(salida, image)
	if outputf != None:
		print("[Atención] Se ha creado una nueva imagen limpia. Se recomienda deshacerse de la imagen original que aún contiene los datos ocultos.")
	
	logInfo("Se han limpiado los datos en la imagen con éxito.")



### EXTRA ###
verbose = False

def logInfo(txt: str) -> None:
	global verbose
	if verbose:	print("[Info] "+txt)


### MAIN ###
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Herramienta de estenografía para imágenes')
	requiredNamed = parser.add_argument_group('Argumentos obligatorios')
	requiredNamed.add_argument('ACCION', help='Acción a realizar entre: HIDE, UNHIDE, CLEAN')
	requiredNamed.add_argument('--in', dest='input', help='Imagen contenedor de entrada.', required=True)
	parser._optionals.title = "Argumentos opcionales"
	parser.add_argument('-v', action='store_true', dest='v', help='Verbose. Escribe más texto por pantalla.')
	parser.add_argument('--out', dest='output', help='En modo HIDE y CLEAN: Indica la imagen de salida (por defecto sobreescribe la imagen de entrada). En modo UNHIDE: Ruta donde desocultar los datos (por defecto los desoculta en el pwd).', required=False)
	parser.add_argument('--hide', dest='hide', help='Obligatorio en modo HIDE: Indica el archivo o carpeta a ocultar.', required=False)
	parser.add_argument('--pass', dest='passwd', help='Opcional en modo HIDE: Indica una contraseña para cifrar los datos ocultos.', required=False)
	args = parser.parse_args()


	verbose = args.v
	if str.upper(args.ACCION)=="HIDE":
		hide(args.input, args.hide, args.output, args.passwd)

	elif str.upper(args.ACCION)=="UNHIDE":
		unhide(args.input, args.output, args.passwd)

	elif str.upper(args.ACCION)=="CLEAN":
		clean(args.input, args.output)

	else:
		print("No se entiende "+args.ACCION+". Solo se admite HIDE, UNHIDE o CLEAN")