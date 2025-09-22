import socket, ssl, threading, subprocess

SERVER_IP   = "192.168.100.102"
CIP_PORT    = 44818   # porta CIP in chiaro (server interno)
TLS_PORT    = 2221    # porta CIP Security TLS

# 1. Avvia il server CIP in chiaro (come nel server.py precedente) su 44818
cip_server_proc = subprocess.Popen([
    "python", "-m", "cpppo.server.enip", 
    "--address", f"{SERVER_IP}:{CIP_PORT}", 
    "Sensor=INT"
])
# (Il processo rimane in esecuzione; non usiamo --print per non appesantire l'output)

# 2. Configura contesto TLS con certificato self-signed (già esistente)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# 3. Crea socket TCP in ascolto su SERVER_IP:2221
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((SERVER_IP, TLS_PORT))
sock.listen(5)
print(f"[*] Server TLS in ascolto su {SERVER_IP}:{TLS_PORT} ...")

def handle_tls_client(tls_conn: ssl.SSLSocket):
    """Inoltra i dati tra il client TLS e il server CIP in chiaro."""
    try:
        # Apri connessione al server CIP locale (in chiaro)
        backend = socket.create_connection((SERVER_IP, CIP_PORT))
        print("[+] Client TLS connesso - aperta conn. al CIP server locale")
        # Thread per inoltrare dal client TLS al server CIP
        def forward_in():
            while True:
                data = tls_conn.recv(4096)
                if not data: break
                backend.sendall(data)
        # Thread per inoltrare dal server CIP al client TLS
        def forward_out():
            while True:
                data = backend.recv(4096)
                if not data: break
                tls_conn.sendall(data)
        t_in = threading.Thread(target=forward_in, daemon=True)
        t_out = threading.Thread(target=forward_out, daemon=True)
        t_in.start(); t_out.start()
        t_in.join(); t_out.join()
    finally:
        tls_conn.close()
        backend.close()
        print("[-] Connessione TLS terminata.")

# Loop di accettazione connessioni TLS
try:
    while True:
        client_sock, addr = sock.accept()  # accetta socket TCP grezzo
        # Effettua handshake TLS
        tls_conn = context.wrap_socket(client_sock, server_side=True)
        # Lancia thread per gestire la connessione TLS appena autenticata
        threading.Thread(target=handle_tls_client, args=(tls_conn,), daemon=True).start()
except KeyboardInterrupt:
    print("[*] Chiusura server TLS...")
    sock.close()
    cip_server_proc.kill()
