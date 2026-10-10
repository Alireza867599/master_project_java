import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/** Port of the MPC shuffle, bubble-sort, and clearing wire protocol shared by p0.cpp and p1.cpp.
 *  Java signed longs intentionally implement uint64 arithmetic modulo 2^64.
 */
public final class AuctioneerMpc {
    private static final SecureRandom RANDOM = new SecureRandom();
    public static final class Dataset {
        public final int kind;
        public final boolean descending;
        public final String label;
        public final List<String> names;
        public final long[] bidShares, idShares;
        public Dataset(int kind,List<String> names,long[] bid,long[] ids) {
            if(bid.length!=ids.length || bid.length!=names.size())throw new IllegalArgumentException("dataset length mismatch");
            this.kind=kind; this.descending=kind==0; this.label=(kind==0?"buyer bids (descending)":"seller asks (ascending)");
            this.names=List.copyOf(names); this.bidShares=bid.clone(); this.idShares=ids.clone();
        }
    }
    public static final class Sorted {
        public final Dataset dataset;
        public final long[] bids, ids, peerBids, peerIds, reconstructedIds, perm;
        Sorted(Dataset d,long[] b,long[] i,long[] pb,long[] pi,long[] ri,long[] p){dataset=d;bids=b;ids=i;peerBids=pb;peerIds=pi;reconstructedIds=ri;perm=p;}
    }
    public static final class Clearing {
        public final long k, pb, ps;
        public final long[] buyerIds,sellerIds;
        Clearing(long k,long pb,long ps,long[] buyerIds,long[] sellerIds){this.k=k;this.pb=pb;this.ps=ps;this.buyerIds=buyerIds;this.sellerIds=sellerIds;}
        public Map<String,Object> toJson() {return SimpleJson.map("K", Long.toUnsignedString(k),"Pb",Long.toUnsignedString(pb),"Ps",Long.toUnsignedString(ps),
            "winningBuyerIds", unsigned(buyerIds),"winningSellerIds",unsigned(sellerIds));}
    }
    public static List<String> unsigned(long[] a){List<String> r=new ArrayList<>();for(long x:a)r.add(Long.toUnsignedString(x));return r;}
    public static long[] shuffle(long[] c,long[] a,long[] b,long[] e,long[] f,int n,boolean publicTerm){
        long[] result=c.clone();
        for(int col=0;col<n;col++)for(int row=0;row<n;row++){
            int offset=row*n+col;
            result[col]+=e[row]*b[offset]+a[row]*f[offset]+(publicTerm?e[row]*f[offset]:0);
        }
        return result;
    }
    public static long[] permutation(long[] original,long[] sorted){
        // Match C++ compute_perm_from_ids: stable handling of duplicate IDs is forbidden.
        if(original.length!=sorted.length)throw new IllegalArgumentException("permutation size mismatch");
        Map<Long,Integer> positions=new HashMap<>();
        for(int i=0;i<original.length;i++)if(positions.put(original[i],i+1)!=null)throw new IllegalArgumentException("duplicate bidder IDs");
        long[] result=new long[sorted.length];
        for(int i=0;i<sorted.length;i++){
            Integer pos=positions.get(sorted[i]);if(pos==null)throw new IllegalArgumentException("sorted bidder ID not in original dataset");
            result[i]=pos;
        }
        return result;
    }
    public static final class Channel {
        final DataInputStream in; final DataOutputStream out; final Socket socket;
        Channel(Socket sock)throws IOException{socket=sock;in=new DataInputStream(new BufferedInputStream(sock.getInputStream(),65536));out=new DataOutputStream(new BufferedOutputStream(sock.getOutputStream(),65536));}
        long get()throws IOException{return in.readLong();}
        void put(long n)throws IOException{out.writeLong(n);out.flush();}
        void putPair(long a,long b)throws IOException{out.writeLong(a);out.writeLong(b);out.flush();}
        long[] getPair()throws IOException{return new long[]{in.readLong(),in.readLong()};}
        long[] getVector(int n)throws IOException{if(n<0||n>10_000_000)throw new IOException("invalid vector size");long[] v=new long[n];for(int i=0;i<n;i++)v[i]=in.readLong();return v;}
        void putVector(long[] v)throws IOException{for(long x:v)out.writeLong(x);out.flush();}
        void putStrings(List<String> v)throws IOException{out.writeLong(v.size());for(String s:v)Wire.writeString(out,s);out.flush();}
        List<String> getStrings()throws IOException{long n=get();if(n<0||n>1000000)throw new IOException("bad names length");List<String> v=new ArrayList<>();for(int i=0;i<n;i++)v.add(Wire.readString(in,1<<20));return v;}
    }
    private final int party;
    private final Channel peer,p2;
    private final Map<Integer,Sorted> completed=new LinkedHashMap<>();
    public AuctioneerMpc(int party,Socket peerSocket,Socket p2Socket)throws IOException{if(party!=0 && party!=1)throw new IllegalArgumentException("party");this.party=party;peer=new Channel(peerSocket);p2=new Channel(p2Socket);}
    static int size(long v,String label){if(v<0||v>2000)throw new IllegalArgumentException(label+" too large for safe MPC memory allocation: "+Long.toUnsignedString(v));return (int)v;}
    static long[] subtract(long[] v,long[] mask){long[] r=new long[v.length];for(int i=0;i<v.length;i++)r[i]=v[i]-mask[i];return r;}
    static long[] add(long[] a,long[] b){long[] r=new long[a.length];for(int i=0;i<a.length;i++)r[i]=a[i]+b[i];return r;}
    private long[] exchange(long[] local)throws IOException{
        if(party==0){peer.putVector(local);return peer.getVector(local.length);}
        else {long[] remote=peer.getVector(local.length);peer.putVector(local);return remote;}
    }
    private long[] exchangePair(long a,long b)throws IOException{
        if(party==0){peer.putPair(a,b);return peer.getPair();}
        else{long[] theirs=peer.getPair();peer.putPair(a,b);return theirs;}
    }
    private long[] exchangeScalar(long v)throws IOException{
        if(party==0){peer.put(v);return new long[]{peer.get()};}
        else{long p=peer.get();peer.put(v);return new long[]{p};}
    }
    private record Triple(long a,long b,long c){}
    private static Triple triple(long[] flat,int at){return new Triple(flat[at],flat[at+1],flat[at+2]);}
    private long beaver(long x,long y,Triple t)throws IOException{
        long d=x-t.a,e=y-t.b;
        long[] other=exchangePair(d,e);d+=other[0];e+=other[1];
        return t.c +d*t.b+e*t.a+(party==0?d*e:0);
    }
    private long compare(long lhs,long rhs,Triple t)throws IOException{
        long rand=(RANDOM.nextLong()&0x7fffffffL)<<1 | (party==0?1:0);
        long masked=beaver(lhs-rhs,rand,t);
        p2.put(masked);
        return p2.get();
    }
    public Map<Integer,Sorted> sort(List<Dataset> runs)throws IOException{
        if(party==0){peer.put(runs.size());p2.put(runs.size());}
        else if(peer.get()!=runs.size())throw new IOException("dataset count mismatch");
        for(Dataset dataset:runs){
            int n=dataset.bidShares.length;
            if(n<0 || n>2000)throw new IOException("dataset size outside safe bounds");
            if(party==0){peer.put(dataset.kind);peer.put(n);peer.put(dataset.descending?1:0);
                p2.put(dataset.kind);p2.put(n);p2.put(dataset.descending?1:0);
            }else{
                if(peer.get()!=dataset.kind||peer.get()!=n||peer.get()!=(dataset.descending?1:0))throw new IOException("dataset metadata mismatch");
            }
            long[] bids=dataset.bidShares.clone(),ids=dataset.idShares.clone();
            long[] origIds=ids.clone();
            long[] remoteOrigIds=exchange(origIds);
            long[] aBid=p2.getVector(n),cBid=p2.getVector(n),aId=p2.getVector(n),cId=p2.getVector(n);
            int square=Math.multiplyExact(n,n);
            long[] b=p2.getVector(square),w=p2.getVector(square);
            long[] eb=add(subtract(bids,aBid),exchange(subtract(bids,aBid)));
            long[] ei=add(subtract(ids,aId),exchange(subtract(ids,aId)));
            long[] f=add(subtract(w,b),exchange(subtract(w,b)));
            bids=shuffle(cBid,aBid,b,eb,f,n,party==0);
            ids=shuffle(cId,aId,b,ei,f,n,party==0);
            int comparisons=Math.multiplyExact(n,n-1)/2;
            int total=size(p2.get(),"triple count");
            if(total!=Math.multiplyExact(comparisons,5))throw new IOException("sort triple count mismatch");
            long[] flat=p2.getVector(Math.multiplyExact(total,3));
            int cursor=0;
            for(int pass=0;pass<n-1;pass++)for(int i=0;i<n-1-pass;i++){
                int j=i+1;
                Triple t2=triple(flat,cursor),fy=triple(flat,cursor+3),fx=triple(flat,cursor+6),iy=triple(flat,cursor+9),ix=triple(flat,cursor+12);
                cursor+=15;
                long flag=compare(bids[i],bids[j],t2);
                long yi=bids[j]-bids[i],xi=-yi;
                long swy=beaver(flag,yi,fy),swx=beaver(flag,xi,fx);
                bids[i]+=swy;bids[j]+=swx;
                long idy=ids[j]-ids[i];
                long siY=beaver(flag,idy,iy),siX=beaver(flag,-idy,ix);
                ids[i]+=siY;ids[j]+=siX;
            }
            long[] peerBids=exchange(bids),peerIds=exchange(ids);
            long[] idsTotal=add(ids,peerIds);
            long[] perm=permutation(add(origIds,remoteOrigIds),idsTotal);
            Sorted res=new Sorted(dataset,bids,ids,peerBids,peerIds,idsTotal,perm);
            completed.put(dataset.kind,res);
            System.out.println("P"+party+": sorted "+dataset.label+"; permutation="+Arrays.toString(perm));
        }
        return Collections.unmodifiableMap(completed);
    }
    public Clearing clear()throws IOException{
        boolean hasBoth=completed.containsKey(0)&&completed.containsKey(1);
        boolean clearing;
        if(party==0){clearing=hasBoth;peer.put(clearing?1:0);p2.put(clearing?1:0);}
        else{clearing=peer.get()!=0;p2.put(clearing?1:0);if(clearing!=hasBoth)throw new IOException("clearing status mismatch");}
        if(!clearing)return new Clearing(0,0,0,new long[0],new long[0]);
        Sorted buyers=completed.get(0),sellers=completed.get(1);
        int nb=buyers.bids.length,ns=sellers.bids.length;
        if(party==0){peer.put(nb);peer.put(ns);p2.put(nb);p2.put(ns);}
        else{if(peer.get()!=nb||peer.get()!=ns)throw new IOException("clearing size mismatch");}
        int pairs=Math.min(nb,ns);
        int total=size(p2.get(),"clearing triple count");
        if(total!=pairs*6)throw new IOException("clearing triples size mismatch");
        long[] flat=p2.getVector(Math.multiplyExact(total,3));
        long kshare=0;
        for(int k=0;k<pairs;k++){
            int off=k*18;
            long ge=compare(buyers.bids[k],sellers.bids[k],triple(flat,off));
            long neq=party==0?1:0;
            if(k>0){
                long forward=compare(buyers.bids[k],buyers.bids[k-1],triple(flat,off+3));
                long reverse=compare(buyers.bids[k-1],buyers.bids[k],triple(flat,off+6));
                long eq=beaver(forward,reverse,triple(flat,off+9));
                neq-=eq;
            }
            long finalFlag=beaver(ge,neq,triple(flat,off+12));
            long target=(party==0?k+1:0)-kshare;
            kshare+=beaver(finalFlag,target,triple(flat,off+15));
        }
        long k=kshare+exchangeScalar(kshare)[0];
        if(k<=0||k>pairs)return new Clearing(0,0,0,new long[0],new long[0]);
        int idx=(int)k-1; long pb=buyers.bids[idx]+buyers.peerBids[idx],ps=sellers.bids[idx]+sellers.peerBids[idx];
        return new Clearing(k,pb,ps,Arrays.copyOf(buyers.reconstructedIds,idx),Arrays.copyOf(sellers.reconstructedIds,idx));
    }
}
