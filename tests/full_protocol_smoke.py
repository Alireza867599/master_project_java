#!/usr/bin/env python3
"""Bidder + BidderBoss Java interoperability smoke test using deterministic Node mocks.
The Node mocks do NOT validate BabyJub/Ethereum security; they test command
invocation, signed wire framing, encrypted share decryption, Merkle and relay.
"""
import os, sys, json, time, struct, socket, hashlib, tempfile, threading, subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT=Path(__file__).resolve().parents[1]; CP=str(ROOT/'classes')
def U(n):return struct.pack('>Q',n)
def recv_exact(f,n):
    out=b''
    while len(out)<n:
        t=f.recv(n-len(out))
        if not t:raise EOFError('unexpected eof')
        out+=t
    return out
def ru(f):return struct.unpack('>Q',recv_exact(f,8))[0]
def rs(f):return recv_exact(f,ru(f)).decode()
def encstr(t):b=t.encode();return U(len(b))+b
def hybrid(f):
    eph=recv_exact(f,33);iv=recv_exact(f,12);tag=recv_exact(f,16);ct=recv_exact(f,ru(f))
    return eph,iv,tag,ct
def hbytes(h):e,iv,tag,ct=h;return e+iv+tag+U(len(ct))+ct
def packet(f,session,party,role,name,ident,domain,cx,cy):
    bid=hybrid(f);theid=hybrid(f)
    ax,ay,z=rs(f),rs(f),rs(f)
    signature=recv_exact(f,64)
    eth,commit,sigma,res=rs(f),rs(f),rs(f),rs(f)
    tr=encstr('SFDAC-BIDDER-SIGNED-PACKET-V3')+U(session)+U(party)
    tr+=encstr(role)+encstr(name)+U(ident)+encstr(domain)+encstr(cx)+encstr(cy)
    tr+=hbytes(bid)+hbytes(theid)+encstr(ax)+encstr(ay)+encstr(z)
    tr+=encstr(sigma)+encstr(eth)+encstr(commit)
    return bid,theid,signature,tr

MOCK_JS=r'''const fs=require('fs'),crypto=require('crypto'),path=require('path');
let fname=path.basename(process.argv[1]);let a=process.argv.slice(2);
function get(k){let i=a.indexOf('--'+k);return i<0?'':a[i+1];}
const sha=s=>'0x'+crypto.createHash('sha256').update(s).digest('hex');
if(fname=='babyjub_commit.js')console.log(JSON.stringify({Cx:a[1],Cy:a[2]}));
else if(fname=='babyjub_schnorr_open.js')console.log(JSON.stringify({Ax:'12',Ay:'19',z:'25'}));
else if(fname=='mock_derive.js')console.log(JSON.stringify({Hx:'4',Hy:'5'}));
else if(fname=='mock_sigma.js'){fs.mkdirSync(path.dirname(get('out')),{recursive:true});fs.writeFileSync(get('out'),'{"proof":"mock"}');console.log('{"ok":true}');}
else if(fname=='mock_sign.js')console.log('{"signature":"0xmocksignature"}');
else if(fname=='mock_receipt.js'){let p=get('party-id');console.log(JSON.stringify({receiptHash:sha('receipt-'+p),leafHash:sha('leaf-'+p),signature:'0xreceipt'}));}
else if(fname=='mock_submit.js'){
let obj={buyer0:get('buyer-p0-root'),buyer1:get('buyer-p1-root'),seller0:get('seller-p0-root'),seller1:get('seller-p1-root')};
fs.writeFileSync('mock_roots.json',JSON.stringify(obj));console.log('{"ok":true}');}
else if(fname=='mock_read.js'){
let obj=JSON.parse(fs.readFileSync('mock_roots.json'));console.log(JSON.stringify({root:obj[get('role')+get('party-id')]}));}
else throw new Error('unknown mock '+fname);
'''

def run():
    with tempfile.TemporaryDirectory(prefix='java-auction-smoke-') as name:
        cwd=Path(name);(cwd/'keys').mkdir();(cwd/'onchain').mkdir()
        (cwd/'mock.js').write_text(MOCK_JS)
        for n in ['babyjub_commit.js','babyjub_schnorr_open.js','mock_derive.js','mock_sigma.js','mock_sign.js','mock_receipt.js','mock_submit.js','mock_read.js']:
            (cwd/n).symlink_to('mock.js')
        sk0=ec.generate_private_key(ec.SECP256K1());sk1=ec.generate_private_key(ec.SECP256K1())
        for k,sk in enumerate([sk0,sk1]):
            pub=sk.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            (cwd/f'keys/p{k}.elg.pub').write_text(pub.hex())
            (cwd/f'keys/p{k}.babyjub.pub.json').write_text('{"x":"1","y":"2"}')
        seed=os.urandom(32);(cwd/'keys/Alice.priv').write_text(seed.hex());(cwd/'keys/Alice.eth.priv').write_text('123')
        (cwd/'keys/boss.eth.priv').write_text('456')
        outputs={};failures=[]
        def receiver(p):
            try:
                srv=socket.socket();srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                srv.bind(('127.0.0.1',7000+p));srv.listen(8);srv.settimeout(25)
                values=[]
                for _ in range(2):
                    c,_=srv.accept();c.settimeout(20)
                    with c:
                        magic=rs(c);session=ru(c);party=ru(c)
                        role,name=rs(c),rs(c);ident=ru(c);domain=rs(c)
                        c0x,c0y,c1x,c1y=[rs(c) for j in range(4)]
                        if magic=='SFDAC-MERKLE-EVIDENCE-V1':
                            rh,lh,rsig,root=[rs(c) for j in range(4)]
                            steps=ru(c)
                            for j in range(steps):rs(c);ru(c)
                            esig,vsig=rs(c),rs(c)
                        elif magic!='SFDAC-AUCTIONEER-DIRECT-V1':raise AssertionError('unexpected magic '+magic)
                        bid,idp,edsig,tr=packet(c,session,party,role,name,ident,domain,c0x if p==0 else c1x,c0y if p==0 else c1y)
                        ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().verify(edsig,tr)
                        vals=[]
                        for e,iv,tag,ct in (bid,idp):
                            ss=([sk0,sk1][p]).exchange(ec.ECDH(),ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(),e))
                            vals.append(int.from_bytes(AESGCM(hashlib.sha256(ss).digest()).decrypt(iv,ct+tag,None),'big'))
                        values.append((magic,vals))
                outputs[p]=values
                srv.close()
            except Exception as ex:failures.append(f'receiver p{p}: {ex}')
        threads=[threading.Thread(target=receiver,args=(p,),daemon=True) for p in range(2)]
        for t in threads:t.start()
        baseBoss=['java','-cp',CP,'BidderBoss','--nbuyers','1','--nsellers','0','--listen','7500','--session-id','0',
            '--chain-rpc','http://127.0.0.1:8545','--auction-registry','0xmock','--eth-priv','keys/boss.eth.priv',
            '--sign-receipt-tool','mock_receipt.js','--sign-merkle-evidence-tool','mock_sign.js',
            '--sign-commitment-vector-tool','mock_sign.js','--submit-roots-tool','mock_submit.js']
        baseBid=['java','-cp',CP,'Bidder','--mode','submit','--boss','127.0.0.1','--port','7500',
            '--session-id','0','--role','buyer','--name','Alice','--bid','90','--id','101',
            '--chain-rpc','http://127.0.0.1:8545','--auction-registry','0xmock',
            '--eth-priv','keys/Alice.eth.priv','--derive-commitment-h-tool','mock_derive.js',
            '--sigma-cce-proof-tool','mock_sigma.js','--cce-packet-sign-tool','mock_sign.js',
            '--commitment-packet-sign-tool','mock_sign.js','--read-root-tool','mock_read.js',
            '--path-check-delay-sec','0','--out','receipt.json']
        boss=subprocess.Popen(baseBoss,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        try:
            time.sleep(.25)
            bidder=subprocess.run(baseBid,cwd=cwd,timeout=35,capture_output=True,text=True)
            if bidder.returncode:raise AssertionError('Bidder exit='+str(bidder.returncode)+'\n'+bidder.stdout+'\n'+bidder.stderr)
            for t in threads:t.join(timeout=20)
            if failures:raise AssertionError('; '.join(failures))
            if len(outputs)!=2:raise AssertionError('missing direct or relay outputs: '+str(outputs))
            for p in (0,1):
                pair=outputs[p];assert len(pair)==2
                assert {pair[0][0],pair[1][0]}=={'SFDAC-AUCTIONEER-DIRECT-V1','SFDAC-MERKLE-EVIDENCE-V1'}
                assert pair[0][1]==pair[1][1],'relayed encrypted shares differ from direct packets'
            b=sum(outputs[p][0][1][0] for p in (0,1))%(1<<64)
            ident=sum(outputs[p][0][1][1] for p in (0,1))%(1<<64)
            assert (b,ident)==(90,101),(b,ident)
            receipt=json.loads((cwd/'receipt.json').read_text())
            assert receipt['p0Root']==receipt['p0LeafHash']
            assert receipt['p1Root']==receipt['p1LeafHash']
            assert 'inclusion P0=true P1=true' in bidder.stdout,bidder.stdout
            with socket.create_connection(('127.0.0.1',7700),timeout=5) as s:
                s.sendall(encstr('p0')+U(0));assert ru(s)==1
                assert (rs(s),rs(s),ru(s))==('buyer','Alice',101)
                assert rs(s).isdigit()
            print('PASS: Bidder + BidderBoss TCP, Ed25519 verification, secp256k1 decrypt, roots/paths, relay, randomness reveal')
        finally:
            boss.kill()
            try:out=boss.communicate(timeout=5)[0]
            except:out=''
            if failures:print(out)
if __name__=='__main__':run()
