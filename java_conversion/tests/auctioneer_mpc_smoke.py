#!/usr/bin/env python3
"""Full P0/P1/P2 interop in Java using synthetic encrypted-share replacement (not security/chain test)."""
import subprocess,json,tempfile,time,sys,pathlib,random,os
base=pathlib.Path(__file__).resolve().parents[1]
classpath=str(base/'classes')
for n in (1,2,3,4):
    with tempfile.TemporaryDirectory(prefix='auctioneer-java-') as path:
        work=pathlib.Path(path)
        rng=random.Random(1234+n)
        buyers=[(f'B{i+1}',100-i*10+((i*5)%3),1000+i) for i in range(n)]
        sellers=[(f'S{i+1}',10+i*13,2000+i) for i in range(n)]
        all_data=[]
        for data in (buyers,sellers):
            rows=[]
            for nm,bid,ident in data:
                sh_b=rng.getrandbits(64);sh_i=rng.getrandbits(64)
                rows.append((nm,bid,ident,sh_b,sh_i))
            all_data.append(rows)
        for party in (0,1):
            doc={}
            for j,kind in enumerate(('buyers','sellers')):
                doc[kind]={'records':[{'name':nm,'bid_share':str(sh_b if party==0 else (bid-sh_b)%(2**64)),
                 'id_share':str(sh_i if party==0 else (ident-sh_i)%(2**64))} for nm,bid,ident,sh_b,sh_i in all_data[j]]}
            (work/f'p{party}.json').write_text(json.dumps(doc))
        cmds=[]
        for party in (0,1):
            cmds.append(['java','-cp',classpath,f'P{party}','--buyers','--sellers',
                '--test-shares-json',str(work/f'p{party}.json'),'--disable-chain-submit','--disable-result-submit','--disable-prover-send',
                '--sharebids-out',str(work/f'shares{party}.json'),
                '--reveal-out',str(work/f'reveal{party}.json')])
        proc=[]
        try:
            for cmd in cmds:
                proc.append(subprocess.Popen(cmd,cwd=work,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True))
            time.sleep(.6)
            proc.append(subprocess.Popen(['java','-cp',classpath,'P2'],cwd=work,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True))
            outputs=[]
            for p in proc:
                out,_=p.communicate(timeout=40);outputs.append(out)
                if p.returncode!=0:print('FAILED party',proc.index(p),'n',n,'return',p.returncode,'output',out,file=sys.stderr)
            if any(p.returncode for p in proc):sys.exit(1)
            for party in (0,1):
                for j,data in enumerate(all_data):
                    p=json.loads((work/f'permutation_{j}_p{party}.json').read_text())['perm_1based']
                    reconstructed=[data[int(k)-1][1] for k in map(int,p)]
                    expected=sorted([x[1] for x in data],reverse=(j==0))
                    if reconstructed!=expected:
                        print('sort mismatch n=',n,'party',party,'dataset',j,'got',reconstructed,'expect',expected,sep=' ',file=sys.stderr)
                        for out in outputs:print(out,file=sys.stderr)
                        sys.exit(1)
            a=json.loads((work/'onchain/p0_auction_result_session0.json').read_text())
            b=json.loads((work/'onchain/p1_auction_result_session0.json').read_text())
            assert a==b,(a,b)
            print(f'P0/P1/P2 integration n={n}: passed, sort permutations and clearing agreement; result K={a["K"]}')
        finally:
            for p in proc:
                if p.poll() is None:p.kill();p.wait()
print('ALL AUCTIONEER MPC TESTS PASSED')
