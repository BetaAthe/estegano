# estegano
Software de esteganografía sobre imágenes

El software se ejecuta por líneas de comandos tal que:
```
$ python3 estegano.py HIDE --in entrada.png --out salida.png --hide ./carpeta --pass Contraseña -v
```
Los argumentos son:
- **ACCION**: Entre HIDE, UNHIDE y CLEAN, para ocultar datos, recuperarlos y limpiar la imagen contenedora respectivamente.
- **--in**: Imagen contenedora de entrada.
- **--out**: Imagen contenedora de salida.
- **--hide**: Archivo o carpeta a ocultar dentro de la imagen contenedora.
- **--pass**: Contraseña personalizada para ocultar o desocultar datos.
- **-v**: Verbose. Escribe información sobre lo que hace el software por pantalla.

Argumentos como *--pass* usados en momentos que no tengan sentido, como con la acción *CLEAN*, serán ignorados. Aunque no se establezca el argumento *-v*, el programa notificará de los errores que se encuentre, como un archivo no encontrado o que resulte imposible ocultar los datos en la imagen.

La aplicación notificará, como advertencias, consideraciones que el usuario debiera conocer aún realizando exitosamente su tarea. Por ejemplo, a la hora de ocultar datos, si se indica un argumento *--out*,el programa recomendará deshacerse de la imagen original para dificultar el ataque de estegoanálisis por comparación con el archivo original.

También avisará si el tamaño de los datos ocultos en relación a la imagen es demasiado grande como para volverse propenso a perder contra un ataque de estegoanálisis visual.

El uso recomendado del software es el siguiente:
- Ocultar los datos con contraseña.
- Ocultar datos lo más pequeños posibles en una imagen lo más grande posible, buscando acercarse lo máximo posible a n=256. Esto se puede comprobar a la hora de ocultar los datos con el argumento *-v*.
- No conservar la imagen original después de la operación.
- Que la imagen contenedora sea una fotografía natural en formato png.

Con estas recomendaciones, la detección de información oculta es muy improbable y la recuperación del dato oculto es imposible, excepto si se fuerza al usuario a introducir la contraseña. Bajo estos términos, existe cierto grado de negación plausible, aunque el software no tiene implementado ningún tipo de característica que la soporte eficazmente. Se recomienda que el usuario acompañe esta imagen de otras con información oculta no sensible o, incluso, ruído, para intentar distorsionar el perfil de ruido de la cámara con la que se sacaron estas imágenes.
