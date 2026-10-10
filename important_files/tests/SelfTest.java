import java.math.*;
import java.util.*;
import java.security.*;
import java.nio.file.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;

public class SelfTest {
    static void check(boolean good,String message){if(!good)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception{
        Object parsed=SimpleJson.parse("{\"n\":18446744073709551615,\"b\":true,\"s\":\"a\\n\\\"b\",\"a\":[3,null]}");
        check(parsed.equals(SimpleJson.parse(SimpleJson.stringify(parsed))),"JSON roundtrip");
        check(SimpleJson.uint(SimpleJson.object("{\"n\":18446744073709551615}"),"n",0)==-1L,"JSON u64");
        long[] row={1L,-1L},matrix={2,3,4,5};
        check(Arrays.equals(P2.rowTimesMatrix(row,matrix,2),new long[]{-2L,-2L}),"matrix multiplication wrap");
        for(int i=0;i<1000;i++){long r=P2.randomBounded(17);check(r>=0&&r<17,"bounded RNG");}
        String zero="0x"+"00".repeat(32), one="0x"+"01".repeat(32);
        BidderBoss.MerkleTree t=new BidderBoss.MerkleTree(List.of(zero,one,one));
        BidderBoss.Evidence m=new BidderBoss.Evidence();t.path(m,2);
        byte[] h=BidderBoss.hex32(one);
        for(int k=0;k<m.elements.size();k++){
            byte[] sib=BidderBoss.hex32(m.elements.get(k));
            h=m.directions.get(k)==1?BidderBoss.hashPair(sib,h):BidderBoss.hashPair(h,sib);
        }
        check(BidderBoss.bytes32(h).equals(t.root()),"Merkle path");
        Path temp=Files.createTempFile("secp-test", ".key");
        try{
            SecureRandom rand=new SecureRandom();
            BigInteger secret,ephemeral;
            do{secret=new BigInteger(256,rand);}while(secret.signum()==0||secret.compareTo(Secp256k1Ecies.N)>=0);
            do{ephemeral=new BigInteger(256,rand);}while(ephemeral.signum()==0||ephemeral.compareTo(Secp256k1Ecies.N)>=0);
            Files.writeString(temp,HexFormat.of().formatHex(Secp256k1Ecies.to32(secret)));
            byte[] r=Secp256k1Ecies.compress(Secp256k1Ecies.publicFromPrivate(ephemeral));
            Secp256k1Ecies.Point shared=Secp256k1Ecies.mul(ephemeral,Secp256k1Ecies.publicFromPrivate(secret));
            byte[] key=MessageDigest.getInstance("SHA-256").digest(Secp256k1Ecies.to32(shared.x));
            byte[] iv=new byte[12];rand.nextBytes(iv);
            Cipher encrypt=Cipher.getInstance("AES/GCM/NoPadding");
            encrypt.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));
            String clear="{\"hello\":\"سلام\",\"id\":18446744073709551615}";
            byte[] blob=encrypt.doFinal(clear.getBytes(StandardCharsets.UTF_8));
            String json=SimpleJson.stringify(SimpleJson.map("eph_pub_hex",HexFormat.of().formatHex(r),
                "iv_hex",HexFormat.of().formatHex(iv),"tag_hex",HexFormat.of().formatHex(Arrays.copyOfRange(blob,blob.length-16,blob.length)),
                "ciphertext_hex",HexFormat.of().formatHex(Arrays.copyOfRange(blob,0,blob.length-16))));
            check(Secp256k1Ecies.decrypt(json,temp).equals(clear),"secp256k1 ECIES AES-GCM roundtrip");
            byte[] damaged=Arrays.copyOf(blob,blob.length);damaged[damaged.length-1]^=1;
            String bad=json.replace(HexFormat.of().formatHex(Arrays.copyOfRange(blob,blob.length-16,blob.length)),HexFormat.of().formatHex(Arrays.copyOfRange(damaged,damaged.length-16,damaged.length)));
            boolean rejected=false;
            try{Secp256k1Ecies.decrypt(bad,temp);}catch(javax.crypto.AEADBadTagException expected){rejected=true;}
            check(rejected,"tampered ciphertext must fail");
        }finally{Files.deleteIfExists(temp);}
        System.out.println("PASS: JSON, wrap arithmetic, bounded random, Merkle root/path, secp256k1/AES-GCM/tamper rejection");
    }
}
