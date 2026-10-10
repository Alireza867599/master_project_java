#!/usr/bin/env python3
import sys, json, os, struct, tempfile, pathlib, socket, time, subprocess, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ROOT=pathlib.Path(__file__).resolve().parents[1]
def recv_n(sock,n):
    out=b''
    while len(out)<n:
        new=sock.recv(n-len(out))
        if not new:raise IOError('short read')
        out+=new
    return out
def send_payload(outdir,privPath,sk,payload,port=7958,bad_tag=False):
    eph=ec.generate_private_key(ec.SECP256K1());shared=eph.exchange(ec.ECDH(),sk.public_key())
    key=hashlib.sha256(shared).digest();iv=os.urandom(12)
    plain=json.dumps(payload,separators=(',',':')).encode()
    ciphertext=AESGCM(key).encrypt(iv,plain,None)
    if bad_tag:ciphertext=ciphertext[:-1]+bytes([ciphertext[-1]^1])
    msg=json.dumps({**{k:payload[k] for k in ('party_id','session_id','dataset_kind','sender')},
        'eph_pub_hex':eph.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).hex(),
        'iv_hex':iv.hex(),'tag_hex':ciphertext[-16:].hex(),'ciphertext_hex':ciphertext[:-16].hex()}).encode()
    proc=subprocess.Popen(['java','-cp',str(ROOT/'classes'),'ProverParty','--listen',str(port),
        '--priv',str(privPath),'--out-dir',str(outdir/'payloads'),'--sended-dir',str(outdir),'--once'],
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    try:
        s=None
        for i in range(80):
            try:s=socket.create_connection(('127.0.0.1',port),timeout=1);break
            except OSError:time.sleep(.05)
        assert s is not None
        with s:
            s.sendall(struct.pack('>Q',len(msg))+msg)
            n=struct.unpack('>Q',recv_n(s,8))[0]
            ack=json.loads(recv_n(s,n))
        try:proc.wait(5)
        except subprocess.TimeoutExpired:proc.kill()
        return ack
    finally:proc.kill()

def run():
    with tempfile.TemporaryDirectory(prefix='reveal-') as tmp:
        p=pathlib.Path(tmp);sk=ec.generate_private_key(ec.SECP256K1());priv=p/'priv'
        priv.write_text(sk.private_numbers().private_value.to_bytes(32,'big').hex())
        payload={'sender':'p1','party_id':1,'session_id':23,'dataset_kind':0,
            'payload_type':'auctioneer_dataset_reveal','payload':{'opening':'first'}}
        ack=send_payload(p,priv,sk,payload)
        assert ack['ok'],ack
        payload['payload']['opening']='replacement'
        ack=send_payload(p,priv,sk,payload)
        assert ack['ok'],ack
        doc=json.loads((p/'sended_p1data.json').read_text())
        assert len(doc['records'])==1,doc
        assert doc['records'][0]['signed_payload']['payload']['opening']=='replacement'
        payload['dataset_kind']=1
        ack=send_payload(p,priv,sk,payload)
        assert ack['ok'],ack
        doc=json.loads((p/'sended_p1data.json').read_text())
        assert len(doc['records'])==2
        bad=send_payload(p,priv,sk,payload,bad_tag=True)
        assert not bad['ok'] and ('Tag' in bad['error'] or 'tag' in bad['error']),bad
        print('PASS: ProverParty canonical upsert, second dataset, tamper rejection')
if __name__=='__main__':run()
