import socket, ssl, threading
from cpppo.server.enip import client

SERVER_IP = "192.168.100.102"
TLS_PORT  = 2221
LOCAL_PORT = 44818  # porta locale su cui il client CIP "penserà" di collegarsi

# 1. Instaurazione connessione TLS verso il server
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE
# Se si vuole verificare il certificato, usare:
# ssl_context.load_verify_locations(cafile="cert.pem"); ssl_context.verify_mode = ssl.CERT_REQUIRED

# Crea un socket TLS connesso al server (handshake eseguito qui)
tls_sock = ssl_context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=SERVER_IP)
tls_sock.connect((SERVER_IP, TLS_PORT))
print("[*] Connessione TLS al server stabilita")

# 2. Avvia un piccolo server TCP locale su 127.0.0.1:LOCAL_PORT per ricevere la connessione del client CIP (cpppo)
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind(("127.0.0.1", LOCAL_PORT))
lsock.listen(1)

# Thread che accetta la conn. locale e inoltra dati attraverso tls_sock
def accept_and_forward():
    local_conn, _ = lsock.accept()
    print("[*] Client CIP locale connesso, inizio inoltro dati su TLS")
    try:
        # Thread per inoltrare richieste dal client CIP -> server TLS
        def forward_req():
            while True:
                data = local_conn.recv(4096)
                if not data: break
                tls_sock.sendall(data)
        # Thread per inoltrare risposte dal server TLS -> client CIP
        def forward_res():
            while True:
                data = tls_sock.recv(4096)
                if not data: break
                local_conn.sendall(data)
        t1 = threading.Thread(target=forward_req, daemon=True); t1.start()
        t2 = threading.Thread(target=forward_res, daemon=True); t2.start()
        t1.join(); t2.join()
    finally:
        local_conn.close()
        tls_sock.close()
        lsock.close()
        print("[*] Connessione locale chiusa, TLS terminata.")

# Avvia il thread di forwarding (accetta una sola connessione locale)
threading.Thread(target=accept_and_forward, daemon=True).start()

# 3. Usa la libreria cpppo per connettersi al socket locale e leggere il tag 100k volte (come in client.py)
TAG_NAME = "Sensor"
with client.connector(host="127.0.0.1", port=LOCAL_PORT) as conn:
    with open("times_tls.txt", "w") as f:
        for i in range(100000):
            operations = client.parse_operations([TAG_NAME])
            t0 = ssl.clock() if hasattr(ssl, "clock") else ssl.time()  # or time.perf_counter()
            for idx, descr, op, reply, status, value in conn.synchronous(operations=operations):
                pass  # ottiene il valore (non utilizzato qui)
            t1 = ssl.clock() if hasattr(ssl, "clock") else ssl.time()
            f.write(f"{t1 - t0:.6f}\n")
