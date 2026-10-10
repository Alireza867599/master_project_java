import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Compatible with OpenSSL EC_POINT_mul/secp256k1 + SHA256(sharedX32) + AES-256-GCM. */
public final class Secp256k1Ecies {
    private Secp256k1Ecies() {}
    public static final BigInteger P=new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
    public static final BigInteger N=new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
    private static final BigInteger SEVEN=BigInteger.valueOf(7);
    public static final class Point {
        public final BigInteger x,y;
        public Point(BigInteger x,BigInteger y){this.x=x;this.y=y;}
    }
    private static final Point G=new Point(new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16),new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",16));
    static byte[] hex(String s){
        String t=s.trim();if(t.startsWith("0x")||t.startsWith("0X"))t=t.substring(2);
        if((t.length()&1)!=0)t="0"+t;
        return HexFormat.of().parseHex(t);
    }
    static Point decode(byte[] enc){
        if(enc.length!=33 && enc.length!=65)throw new IllegalArgumentException("invalid secp256k1 point length");
        int prefix=Byte.toUnsignedInt(enc[0]);
        BigInteger x=new BigInteger(1,Arrays.copyOfRange(enc,1,33)),y;
        if(x.compareTo(P)>=0)throw new IllegalArgumentException("EC x outside field");
        if(enc.length==33){
            if(prefix!=2 && prefix!=3)throw new IllegalArgumentException("invalid compressed point prefix");
            BigInteger ySquared=x.modPow(BigInteger.valueOf(3),P).add(SEVEN).mod(P);
            y=ySquared.modPow(P.add(BigInteger.ONE).shiftRight(2),P);
            if(!y.multiply(y).mod(P).equals(ySquared))throw new IllegalArgumentException("point not on curve");
            if(y.testBit(0)!=(prefix==3))y=P.subtract(y);
        }else{
            if(prefix!=4)throw new IllegalArgumentException("invalid uncompressed point prefix");
            y=new BigInteger(1,Arrays.copyOfRange(enc,33,65));
        }
        if(y.compareTo(P)>=0 || !y.multiply(y).mod(P).equals(x.modPow(BigInteger.valueOf(3),P).add(SEVEN).mod(P)))
            throw new IllegalArgumentException("EC point not on curve");
        return new Point(x,y);
    }
    static Point add(Point a,Point b){
        if(a==null)return b;if(b==null)return a;
        if(a.x.equals(b.x)){
            if(!a.y.equals(b.y) || a.y.signum()==0)return null;
            BigInteger m=a.x.multiply(a.x).multiply(BigInteger.valueOf(3)).mod(P)
                .multiply(a.y.shiftLeft(1).mod(P).modInverse(P)).mod(P);
            BigInteger x=m.multiply(m).subtract(a.x.shiftLeft(1)).mod(P);
            return new Point(x,m.multiply(a.x.subtract(x)).subtract(a.y).mod(P));
        }
        BigInteger m=b.y.subtract(a.y).mod(P).multiply(b.x.subtract(a.x).mod(P).modInverse(P)).mod(P);
        BigInteger x=m.multiply(m).subtract(a.x).subtract(b.x).mod(P);
        return new Point(x,m.multiply(a.x.subtract(x)).subtract(a.y).mod(P));
    }
    static Point mul(BigInteger scalar,Point point){
        if(scalar.signum()<=0 || scalar.compareTo(N)>=0)throw new IllegalArgumentException("private scalar out of valid range");
        Point acc=null, cur=point;
        for(int i=0;i<scalar.bitLength();i++){
            if(scalar.testBit(i))acc=add(acc,cur);
            cur=add(cur,cur);
        }
        if(acc==null)throw new IllegalArgumentException("infinite EC shared point");
        return acc;
    }
    static byte[] to32(BigInteger bi){
        byte[] b=bi.toByteArray();
        if(b.length>33 || (b.length==33 && b[0]!=0))throw new IllegalArgumentException("EC coordinate too large");
        byte[] dest=new byte[32];int n=Math.min(32,b.length);
        System.arraycopy(b,b.length-n,dest,32-n,n);
        return dest;
    }
    public static byte[] compress(Point point){
        byte[] b=new byte[33];b[0]=(byte)(point.y.testBit(0)?3:2);System.arraycopy(to32(point.x),0,b,1,32);return b;
    }
    public static Point publicFromPrivate(BigInteger secret){return mul(secret,G);}
    public static String decrypt(String encryptedJson,Path secretPath) throws Exception {
        Map<String,Object> j=SimpleJson.object(encryptedJson);
        byte[] sk=hex(Files.readString(secretPath,StandardCharsets.UTF_8));
        if(sk.length!=32)throw new IllegalArgumentException("private key must be a 32-byte hex scalar");
        byte[] eph=hex(required(j,"eph_pub_hex"));
        byte[] iv=hex(required(j,"iv_hex")),tag=hex(required(j,"tag_hex")),ct=hex(required(j,"ciphertext_hex"));
        if(iv.length!=12 || tag.length!=16)throw new IllegalArgumentException("invalid AES-GCM iv/tag length");
        BigInteger priv=new BigInteger(1,sk);
        Point shared=mul(priv,decode(eph));
        byte[] key=MessageDigest.getInstance("SHA-256").digest(to32(shared.x));
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));
        byte[] all=new byte[ct.length+tag.length];System.arraycopy(ct,0,all,0,ct.length);System.arraycopy(tag,0,all,ct.length,tag.length);
        return new String(cipher.doFinal(all), StandardCharsets.UTF_8);
    }
    static String required(Map<String,Object> j,String key){
        Object v=j.get(key);
        if(!(v instanceof String s) || s.isBlank())throw new IllegalArgumentException("missing JSON hex field "+key);
        return s;
    }
}
