#!/usr/bin/env python3

import socket
import rsa
import hashlib
import time

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
ATTESTER_HOST = HOST
#'192.168.0.219'
PORT_SERVER = 65432 
PORT_CLIENT = 65433
PORT_EPCA = 65434
PORT_VERIFIER = 65435
PORT_ATTESTER = 65436

PROGRAM_HASH = b'931ac7c7ca864c6a9d5979a4c4494780c5ef4795'

# As soon as the server starts, it sends its intermediate symmetric key(for DH) and public key(for RSA) to EPCA
# VREP02
REQ = "VREP01" 
Kv_n = 20099951841200385854307441162633676545561901802337280679552332958523079359527561852605171172676037789507822328408278593402206612033040576463748990996786283713038479993174747107230513838222347464614800926471487337138500853016686302383811877926055162649020762831324090069004252903038204464011257484406545093545244810049139143598771785633473672836503274404963709398352246494832713582088893706682649484193849537201708903655936209144918966437281143127402759564558756896523098931061670617773313709224227073026889521006206920960741548944871190124644757736473753314825772586334428323357660414631085895802672471751961931972543
Kv_e = 65537
Kv_d = 12304960065624009046197855362406361851846881337436471583141113426444671971307891863960389896072986437475675414469208926955611814415942459500771675050460998960141856597130842557474334279923078606402649312158971931173746017118306775377892127413083589127383951440492451861673857984387381193836795033050506349584098100304445359718750255978814679372474545474718348550095301509582526598492866697936553047725804942724591900779799106272028919707407352209930055583713217873485233100648423717086130446601749888427158969055983820611271518732510613728847529175809884242377898883671534812566540715512393908544727185652520127479233
Kv_p = 2832069261582738850869365776752225528733145631112920282857074194303483290978112738683065893015115241005141406622392638787045029267929834571668158043424331332387713780760431480343235605195525930869282955895847163398238419940713528843725882662810525876795211054897217129390877950719945482663146884858144659285820790076103634196513
Kv_q = 7097267045639719124022628431059114338173161111885776722964558180988123213238545648242813063371045749194595665750442517524802450137320960293875396422817124114625427465642628956416676324783747506938611294085586559170786939918741424767903305907312605377014492547155249520122149358388354489311

verifier_pub = rsa.PublicKey(Kv_n, Kv_e)
verifier_priv = rsa.PrivateKey(Kv_n, Kv_e, Kv_d, Kv_p, Kv_q)
server_public_n = 0
server_public_e = 0

data_vrep = 'REQ:' + REQ + '|Kv_n:' + str(Kv_n) + '|Kv_e:' + str(Kv_e)
data_vrep = data_vrep.encode()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_epca:
    s_to_epca.connect((HOST, PORT_EPCA))
    s_to_epca.sendall(data_vrep)
    print("VREP01: SENT PUBLIC KEY TO EPCA\n")
    print("\n---------------------------------------------------------\n")
    

while(True):
    data_cumulative = b''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_verifier:
        s_to_verifier.bind((HOST, PORT_VERIFIER))
        s_to_verifier.listen()
        conn, addr = s_to_verifier.accept()
        with conn:
            while True:
                data = conn.recv(1024)
                if data == b'':
                    break
                #data = data.decode()
                data_cumulative += data

            # Data sent from EP is separated by | and is not encrypted. Hence, if statement is used to check
            # if request is from EP. If so, handle it differently than encrypted data.
            req_type = b''
            if data_cumulative.find(b'EP') != -1:
                fields = data_cumulative.split(b'|')
                req_type = fields[0].split(b':',1)[1]
            else:
                fields = data_cumulative.split(b'|~|')
                data_cumulative = fields[1]    
                req_type = fields[0].split(b':',1)[1]
            if req_type == b'SVVR01':
                # Extract {S, R, A, Ns}Kv
                # Next -> VREP02
                print("SVVR01: RECEIVE RESOURCE PARAMETERS FROM SERVER\n")
                print("\n---------------------------------------------------------\n")
                decrypted = rsa.decrypt(data_cumulative, verifier_priv).decode()
                fields = decrypted.split("|")
                REQ = "VREP02"
                Sth = "Something"
                data_vrep = 'REQ:' + REQ + '|Sth:' + Sth
                data_vrep = data_vrep.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as vrep:
                    vrep.connect((HOST, PORT_EPCA))
                    vrep.sendall(data_vrep)
                    
            elif req_type == b'EPVR01':
                # Extract {cert, A, I, E}Ke
                # Next -> VRSV01
                
                REQ = "VRSV01"
                Nv = "Nv"
                J = "J"
                V = "V"
                Ns = "Ns"
                M = "M"
                data_vrsv = 'REQ:' + REQ + '|Nv:' + Nv + '|J:' + J + '|V:' + V + '|Ns:' + Ns + '|M:' + M
                data_vrsv = data_vrsv.encode('utf8')
                data_vrsv = rsa.encrypt(data_vrsv, rsa.PublicKey(server_public_n, server_public_e))
                data_vrsv = b'REQ:VRSV01|~|' + data_vrsv
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as vrsv:
                    vrsv.connect((HOST, PORT_SERVER))
                    vrsv.sendall(data_vrsv)
                    print("VRSV01: SEND ATTESTATION REQUEST TO SERVER. ULTIMATE DESTINATION - VERIFIER\n")
                    print("\n---------------------------------------------------------\n")
            elif req_type == b'SVVR02':
                # Extract B
                # Next -> #############Finished###############

                decrypted = rsa.decrypt(data_cumulative, verifier_priv)

                print("SVVR02: RECEIVE ATTESTATION DATA FROM ATTESTATOR FORWARDED BY SERVER\n")
                print("\n---------------------------------------------------------\n")
                # Extract hash here and check it with the stored hash
                try:
                    signed = decrypted.split(b'|')[1].split(b':')[1]
                    hasher = hashlib.sha1()
                    hasher.update(signed)

                    dec = rsa.verify(b'ATTESTER', signed, rsa.PublicKey(attester_public_n, attester_public_e))

                except rsa.pkcs1.VerificationError:
                    print("")
                    #print("VERIFICATION FAILED !! POSSIBLE MAN-IN-THE-MIDDLE ATTACK*******")

                hash_value = decrypted.split(b'|')[0].split(b':')[1]
                if hash_value == b'2df26d17e26761f2aefc1614d78496b2343c9eaa':
                    print("***************  SYSTEM IS SAFE  ***************\n")
                    time.sleep(10)
                    REQ = "VREP02"
                    Sth = "Something"
                    data_vrep = 'REQ:' + REQ + '|Sth:' + Sth
                    data_vrep = data_vrep.encode()
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as vrep:
                        vrep.connect((HOST, PORT_EPCA))
                        vrep.sendall(data_vrep)
                else:
                    print("DANGER !! DANGER !! DANGER !!\n")
                    print("THE PROGRAM HAS BEEN MODIFIED")
            elif req_type == b'EPVR02':
                server_public_n = int(fields[1].split(b':',1)[1])
                server_public_e = int(fields[2].split(b':',1)[1])
                attester_public_n = int(fields[3].split(b':',1)[1])
                attester_public_e = int(fields[4].split(b':',1)[1])

            else:
                print("Error in parsing header")
