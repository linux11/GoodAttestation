#!/usr/bin/env python3

import socket
import rsa
import hashlib

ATTESTER_ID = b'ATTESTER'
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
ATTESTER_HOST = HOST
#'192.168.0.219'
PORT_SERVER = 65432 
PORT_CLIENT = 65433
PORT_EPCA = 65434
PORT_VERIFIER = 65435
PORT_ATTESTER = 65436

verifier_public_n = 0
verifier_public_e = 0

(attester_pub, attester_priv) = rsa.newkeys(512)
REQ = "ATEP01" 
Ka_n = attester_pub['n']
Ka_e = attester_pub['e']

data_atep = 'REQ:' + REQ + '|Ka_n:' + str(Ka_n) + '|Ka_e:' + str(Ka_e)
data_atep = data_atep.encode()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_epca:
    s_to_epca.connect((HOST, PORT_EPCA))
    s_to_epca.sendall(data_atep)
    print("ATEP01: SEND PUBLIC KEY TO EPCA\n")
    print("\n---------------------------------------------------------\n")

while(True):
    data_cumulative = ""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_attester:
        s_to_attester.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_to_attester.bind((ATTESTER_HOST, PORT_ATTESTER))
        s_to_attester.listen()
        conn, addr = s_to_attester.accept()
        with conn:
            while True:
                data = conn.recv(1024)
                data = data.decode()
                data_cumulative += data
                if not data:
                    break
            fields = data_cumulative.split("|")
            req_type = fields[0].split(":",1)[1]

            if req_type == "EPAT01":
                verifier_public_n = int(fields[1].split(":",1)[1])
                verifier_public_e = int(fields[2].split(":",1)[1])
                print("EPAT01: RECEIVE VERIFIER PUBLIC KEY FROM EPCA\n")
                print(rsa.PublicKey(verifier_public_n, verifier_public_e))
                print("\n---------------------------------------------------------\n")
            elif req_type == "CLAT01":
                # Extract {S, Nv, J, V, M R}
                # Next -> ATCL01
                print("CLAT01: RECEIVE ATTESTATION REQUEST FORWARDED BY CLIENT\n")
                print("\n---------------------------------------------------------\n")
                REQ = b'ATCL01'
                K_ = b'K_'
                Nv = b'Nv'
                B = b'B'
                # ********* Take hash here, and send it with data_atcl
                BLOCKSIZE = 65536
                hasher = hashlib.sha1()
                with open('TurbineProgram.exe', 'rb') as afile:
                    buf = afile.read(BLOCKSIZE)
                    while len(buf) > 0:
                        hasher.update(buf)
                        buf = afile.read(BLOCKSIZE)
                H = hasher.hexdigest().encode()
                #data_atcl = b'REQ:' + REQ + b'|K_:' + K_ + b'|Nv:' + Nv + b'|B:' + B

                signed = rsa.sign(ATTESTER_ID, attester_priv, 'SHA-1')

                hasher = hashlib.sha1()
                hasher.update(signed)
                data_atcl = b'H:' + H + b'|SIGN:' + signed

                data_atcl = rsa.encrypt(data_atcl, rsa.PublicKey(verifier_public_n, verifier_public_e))

                data_atcl = b'REQ:ATCL01|~|' + data_atcl
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as atcl:
                    atcl.connect((HOST, PORT_CLIENT))
                    atcl.sendall(data_atcl)  
                    print("EPCL01: SEND ATTESTATION RESPONSE TO CILENT. ULTIMATE DESTINATION  - VERIFIER\n")
                    print("\n---------------------------------------------------------\n")

                              
            
