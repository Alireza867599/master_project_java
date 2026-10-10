#!/usr/bin/env python3
"""Bidder/BidderBoss -> P0/P1 -> P2 integration; external cryptographic/on-chain JS helpers MOCKED.
Validates REAL Ed25519 transcript, real secp256k1/AES-GCM, real TCP framing, Merkle, MPC.
NOT an on-chain validity test, nor a BabyJub/CCE soundness test.
"""
import os, sys, json, time, subprocess, tempfile, pathlib
from cryptography.hazmat.primitives.asymmetric import ec,ed25519
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from full_protocol_smoke import MOCK_JS
ROOT=pathlib.Path(__file__).resolve().parents[1]; CP=str(ROOT/'classes')
MOCK_VERIFY='''console.log(JSON.stringify({signatureOk:true,proofOk:true}));'''
def launch(name,args,cwd,procs):
    log=open(cwd/(name+'.log'),'w+')
    p=subprocess.Popen(args,cwd=cwd,stdout=log,stderr=subprocess.STDOUT)
    procs.append((name,p,log));return p

def run():
  with tempfile.TemporaryDirectory(prefix='sfdac-six-java-') as tmp:
    cwd=pathlib.Path(tmp);(cwd/'keys').mkdir();(cwd/'onchain').mkdir();(cwd/'js').mkdir()
    (cwd/'mock.js').write_text(MOCK_JS)
    (cwd/'mock_verify.js').write_text(MOCK_VERIFY)
    for n in ['babyjub_commit.js','babyjub_schnorr_open.js','mock_derive.js','mock_sigma.js','mock_sign.js','mock_receipt.js','mock_submit.js','mock_read.js']:
        (cwd/n).symlink_to('mock.js')
    keys=[]
    for p in (0,1):
        sk=ec.generate_private_key(ec.SECP256K1());keys.append(sk)
        (cwd/f'keys/p{p}.elg.pub').write_text(sk.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).hex())
        (cwd/f'keys/p{p}.elg.priv').write_text(f'{sk.private_numbers().private_value:064x}')
        (cwd/f'keys/p{p}.babyjub.pub.json').write_text('{"x":"1","y":"2"}')
        (cwd/f'keys/p{p}.eth.priv').write_text('abc')
    pubkeys={}
    for name in ('Alice','Bob'):
        ed=ed25519.Ed25519PrivateKey.generate()
        raw=ed.private_bytes_raw();(cwd/f'keys/{name}.priv').write_text(raw.hex())
        pubkeys[name]=ed.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
        (cwd/f'keys/{name}.eth.priv').write_text('111')
    (cwd/'pubkeys.json').write_text(json.dumps(pubkeys));(cwd/'keys/boss.eth.priv').write_text('2')
    procs=[]
    try:
        common=['--buyers','--sellers','--nbuyers','1','--nsellers','1','--chain-rpc','http://127.0.0.1:8545',
          '--perm-registry','0xmock','--pubkeys','pubkeys.json','--read-root-tool','mock_read.js',
          '--cce-verifier','mock_verify.js','--disable-chain-submit','--disable-result-submit','--disable-prover-send']
        launch('p0',['java','-cp',CP,'P0']+common,cwd,procs)
        launch('p1',['java','-cp',CP,'P1']+common,cwd,procs)
        time.sleep(.5)
        boss=['java','-cp',CP,'BidderBoss','--nbuyers','1','--nsellers','1','--listen','7500','--session-id','0',
              '--chain-rpc','http://127.0.0.1:8545','--auction-registry','0xmock','--eth-priv','keys/boss.eth.priv',
              '--sign-receipt-tool','mock_receipt.js','--sign-merkle-evidence-tool','mock_sign.js',
              '--sign-commitment-vector-tool','mock_sign.js','--submit-roots-tool','mock_submit.js']
        launch('boss',boss,cwd,procs)
        def bidder(role,name,bid,ident):
            return ['java','-cp',CP,'Bidder','--mode','submit','--boss','127.0.0.1','--port','7500',
             '--session-id','0','--role',role,'--name',name,'--bid',str(bid),'--id',str(ident),
             '--chain-rpc','http://127.0.0.1:8545','--auction-registry','0xmock',
             '--eth-priv',f'keys/{name}.eth.priv','--derive-commitment-h-tool','mock_derive.js',
             '--sigma-cce-proof-tool','mock_sigma.js','--cce-packet-sign-tool','mock_sign.js',
             '--commitment-packet-sign-tool','mock_sign.js','--read-root-tool','mock_read.js',
             '--path-check-delay-sec','0','--out',f'{name}.json']
        time.sleep(.4)
        launch('alice',bidder('buyer','Alice',90,101),cwd,procs)
        launch('bob',bidder('seller','Bob',20,201),cwd,procs)
        bidderprocs=procs[-2:]
        for name,p,log in bidderprocs:
            rc=p.wait(timeout=85)
            if rc!=0:raise AssertionError(f'{name} failed with {rc}')
        p0=procs[0][1];p1=procs[1][1]
        time.sleep(.4)
        launch('p2',['java','-cp',CP,'P2'],cwd,procs)
        for name,p,log in (procs[0],procs[1],procs[-1]):
            rc=p.wait(timeout=85)
            if rc!=0:raise AssertionError(f'{name} failed with {rc}')
        a=json.loads((cwd/'onchain/p0_auction_result_session0.json').read_text())
        b=json.loads((cwd/'onchain/p1_auction_result_session0.json').read_text())
        assert a==b,(a,b)
        assert a['K']=='1' and a['Pb']=='90' and a['Ps']=='20',a
        assert json.loads((cwd/'permutation_0_p0.json').read_text())['perm_1based']==[1]
        assert json.loads((cwd/'permutation_1_p1.json').read_text())['perm_1based']==[1]
        print('PASS: six Java roles (Bidder buyer/seller, BidderBoss, P0, P1, P2), real signed TCP, Merkle, decrypt, MPC result',a)
        print('WARNING: JavaScript BabyJub/CCE and Ethereum calls are mocked; no security/on-chain correctness claimed')
    except Exception:
        for name,p,log in procs:
            try:
                log.flush();print(f'====== {name} (pid={p.pid} rc={p.poll()}) ======',file=sys.stderr)
                print((cwd/(name+'.log')).read_text()[-10000:],file=sys.stderr)
            except:pass
        raise
    finally:
        for name,p,log in procs:
            if p.poll() is None:p.kill()
            try:p.wait(timeout=3)
            except:pass
            log.close()
if __name__=='__main__':run()
