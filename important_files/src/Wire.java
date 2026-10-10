import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

/** Binary framing identical to C++: unsigned 64-bit integers in big-endian order. */
public final class Wire {
    private Wire() {}
    public static final int MAX_STRING_BYTES = 128 * 1024 * 1024;
    public static long readU64(DataInput in) throws IOException { return in.readLong(); }
    public static void writeU64(DataOutput out, long value) throws IOException { out.writeLong(value); }
    public static String readString(DataInput in) throws IOException { return readString(in, MAX_STRING_BYTES); }
    public static String readString(DataInput in, int max) throws IOException {
        long len = readU64(in);
        if (len < 0 || len > max) throw new IOException("invalid length: " + Long.toUnsignedString(len));
        byte[] bytes = new byte[(int) len];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }
    public static void writeString(DataOutput out, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        writeU64(out, b.length);
        out.write(b);
    }
    public static byte[] readFixed(DataInput in, int n) throws IOException {
        byte[] v = new byte[n]; in.readFully(v); return v;
    }
    public static byte[] readBlob(DataInput in, int max) throws IOException {
        long len = readU64(in);
        if (len < 0 || len > max) throw new IOException("blob size outside limit: " + Long.toUnsignedString(len));
        return readFixed(in, (int)len);
    }
    public static void writeBlob(DataOutput out, byte[] data) throws IOException {
        writeU64(out, data.length); out.write(data);
    }
    public static void writeU64Vector(DataOutput out, long[] values) throws IOException {
        for (long v : values) writeU64(out, v);
    }
    public static Socket connect(String host, int port, int timeoutMillis) throws IOException {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host, port), timeoutMillis);
            if (timeoutMillis > 0) s.setSoTimeout(timeoutMillis);
            s.setTcpNoDelay(true);
            return s;
        } catch (IOException ex) { try {s.close();} catch (IOException ignored) {} throw ex; }
    }
}
