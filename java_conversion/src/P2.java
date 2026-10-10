import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.util.*;

/** Java 21 port of p2.cpp. Operates on Z/(2^64) with Java long wrapping. */
public final class P2 {
    private static final SecureRandom RNG = new SecureRandom();
    private final DataInputStream p0in, p1in;
    private final DataOutputStream p0out, p1out;
    private P2(Socket p0, Socket p1) throws IOException {
        p0in = new DataInputStream(new BufferedInputStream(p0.getInputStream(), 1<<16));
        p1in = new DataInputStream(new BufferedInputStream(p1.getInputStream(), 1<<16));
        p0out = new DataOutputStream(new BufferedOutputStream(p0.getOutputStream(), 1<<16));
        p1out = new DataOutputStream(new BufferedOutputStream(p1.getOutputStream(), 1<<16));
    }
    static long randomBounded(long bound) {
        if(bound == 0) return 0;
        long max = -1L;
        long limit = max - Long.remainderUnsigned(max,bound);
        long v;
        do {v=RNG.nextLong();} while (Long.compareUnsigned(v,limit)>=0);
        return Long.remainderUnsigned(v,bound);
    }
    static long[] rowTimesMatrix(long[] row,long[] matrix,int n){
        long[] result=new long[n];
        for(int col=0;col<n;col++){
            long acc=0;
            for(int k=0;k<n;k++)acc+=row[k]*matrix[k*n+col];
            result[col]=acc;
        }
        return result;
    }
    private static long[] randomVector(int n){long[] v=new long[n];for(int i=0;i<n;i++)v[i]=RNG.nextLong();return v;}
    private static int checkedCount(long n,String label){
        if(n<0 || n>Integer.MAX_VALUE)throw new IllegalArgumentException(label+" too large: "+Long.toUnsignedString(n));
        return (int)n;
    }
    private void share(long[] vector,String label,String dataset) throws IOException {
        long[] a=new long[vector.length],b=new long[vector.length];
        for(int i=0;i<vector.length;i++){a[i]=RNG.nextLong();b[i]=vector[i]-a[i];}
        Wire.writeU64Vector(p0out,a);Wire.writeU64Vector(p1out,b);
        System.out.println("P2: dataset '"+dataset+"' sent shares for "+label);
    }
    private void sendTriples(int count) throws IOException {
        long[] t0=new long[Math.multiplyExact(count,3)],t1=new long[Math.multiplyExact(count,3)];
        for(int i=0;i<t0.length;i+=3){
            long a=RNG.nextLong(),b=RNG.nextLong(),c=a*b;
            t0[i]=RNG.nextLong();t1[i]=a-t0[i];
            t0[i+1]=RNG.nextLong();t1[i+1]=b-t0[i+1];
            t0[i+2]=RNG.nextLong();t1[i+2]=c-t0[i+2];
        }
        Wire.writeU64(p0out,count);Wire.writeU64(p1out,count);
        Wire.writeU64Vector(p0out,t0);Wire.writeU64Vector(p1out,t1);
        p0out.flush();p1out.flush();
    }
    private void sendFlag(boolean truth) throws IOException {
        long mask=RNG.nextLong();
        Wire.writeU64(p0out,mask);Wire.writeU64(p1out,(truth?1L:0L)-mask);
        p0out.flush();p1out.flush();
    }
    private void run() throws IOException {
        int datasetCount=checkedCount(Wire.readU64(p0in),"dataset count");
        for(int d=0;d<datasetCount;d++){
            long datasetKind=Wire.readU64(p0in);
            int n=checkedCount(Wire.readU64(p0in),"dataset size");
            boolean descending=Wire.readU64(p0in)!=0;
            String dataset=(datasetKind==0?"buyer bids":"seller asks")+(descending?" (descending)":" (ascending)");
            int[] perm=new int[n];for(int i=0;i<n;i++)perm[i]=i;
            for(int rem=n;rem>1;rem--){int j=(int)randomBounded(rem);int v=perm[rem-1];perm[rem-1]=perm[j];perm[j]=v;}
            int nn=Math.multiplyExact(n,n);
            long[] w=new long[nn];for(int col=0;col<n;col++)w[perm[col]*n+col]=1;
            long[] aBid=randomVector(n),aId=randomVector(n),b=randomVector(nn);
            long[] cBid=rowTimesMatrix(aBid,b,n),cId=rowTimesMatrix(aId,b,n);
            share(aBid,"bid A vector",dataset);share(cBid,"bid C vector",dataset);
            share(aId,"ID A vector",dataset);share(cId,"ID C vector",dataset);
            share(b,"B matrix",dataset);share(w,"permutation matrix W",dataset);
            p0out.flush();p1out.flush();
            int comparisons=checkedCount(((long)n*(n-1))/2,"comparisons");
            sendTriples(Math.multiplyExact(comparisons,5));
            for(int i=0;i<comparisons;i++){
                long t2=Wire.readU64(p0in)+Wire.readU64(p1in);
                boolean flag=t2>=0;
                sendFlag(descending?!flag:flag);
            }
        }
        long clearing=Wire.readU64(p0in), clearingP1=Wire.readU64(p1in);
        if(clearing!=clearingP1)throw new IOException("P2 clearing flag mismatch");
        if(clearing!=0){
            long buyers=Wire.readU64(p0in),sellers=Wire.readU64(p0in);
            int pairs=checkedCount(Long.compareUnsigned(buyers,sellers)<0?buyers:sellers,"clearing pairs");
            sendTriples(Math.multiplyExact(pairs,6));
            int comparisonTotal=Math.addExact(pairs,pairs>0?Math.multiplyExact(pairs-1,2):0);
            for(int i=0;i<comparisonTotal;i++)sendFlag(Wire.readU64(p0in)+Wire.readU64(p1in)>=0);
        }
    }
    /** Retry until both auctioneers have opened their P2 listeners. */
    static Socket connectRetry(String host,int port)throws Exception{
        IOException last=null;
        for(int attempt=0;attempt<60;attempt++){
            try{return Wire.connect(host,port,10000);}
            catch(IOException ex){last=ex;Thread.sleep(250);}
        }
        throw new IOException("P2 cannot connect to "+host+":"+port,last);
    }
    public static void main(String[] args) {
        if(args.length!=0){System.err.println("Usage: java P2");System.exit(2);}
        try(Socket p0=connectRetry("127.0.0.1",6001);
            Socket p1=connectRetry("127.0.0.1",6002)){
            new P2(p0,p1).run();
        }catch(Exception e){System.err.println("P2 error: "+e.getMessage());System.exit(1);}
    }
}
