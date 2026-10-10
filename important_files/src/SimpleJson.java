import java.math.*;
import java.util.*;

/** Small dependency-free JSON parser/writer. All JSON integer values are BigIntegers. */
public final class SimpleJson {
    private SimpleJson() {}
    public static Object parse(String text) {
        Parser p = new Parser(text);
        Object value = p.value();
        p.white();
        if (p.i != text.length()) throw new IllegalArgumentException("trailing JSON at offset " + p.i);
        return value;
    }
    @SuppressWarnings("unchecked")
    public static Map<String,Object> object(String text) {
        Object o = parse(text);
        if (!(o instanceof Map)) throw new IllegalArgumentException("expected JSON object");
        return (Map<String,Object>)o;
    }
    public static String string(Map<String,Object> obj, String key, String def) {
        Object value = obj.get(key);
        return value instanceof String ? (String)value : def;
    }
    public static long uint(Map<String,Object> obj, String key, long def) {
        Object val = obj.get(key);
        if (val == null) return def;
        try { return Long.parseUnsignedLong(val.toString()); }
        catch (NumberFormatException e) { return def; }
    }
    public static String quote(String s) { return stringify(s); }
    public static String stringify(Object value) {
        StringBuilder b = new StringBuilder(); append(b, value); return b.toString();
    }
    private static void append(StringBuilder b, Object o) {
        if (o == null) { b.append("null"); return; }
        if (o instanceof String s) {
            b.append('"');
            for (int i=0;i<s.length();i++) {
                char c=s.charAt(i);
                switch (c) {
                    case '\\' -> b.append("\\\\"); case '"' -> b.append("\\\"");
                    case '\b' -> b.append("\\b"); case '\f' -> b.append("\\f");
                    case '\n' -> b.append("\\n"); case '\r' -> b.append("\\r");
                    case '\t' -> b.append("\\t");
                    default -> {if (c < 32) b.append(String.format("\\u%04x", (int)c)); else b.append(c);}
                }
            }
            b.append('"'); return;
        }
        if (o instanceof Boolean || o instanceof Number) { b.append(o); return; }
        if (o instanceof Map<?,?> m) {
            b.append('{'); boolean first=true;
            for (var e:m.entrySet()) {if (!first)b.append(','); first=false; append(b, e.getKey().toString()); b.append(':'); append(b,e.getValue());}
            b.append('}'); return;
        }
        if (o instanceof Iterable<?> list) {
            b.append('['); boolean first=true;
            for (Object item:list){if(!first)b.append(',');first=false;append(b,item);}
            b.append(']'); return;
        }
        throw new IllegalArgumentException("unsupported JSON value: " + o.getClass());
    }
    public static Map<String,Object> map(Object... args) {
        if (args.length%2!=0) throw new IllegalArgumentException("pairs expected");
        Map<String,Object> result=new LinkedHashMap<>();
        for(int i=0;i<args.length;i+=2) result.put((String)args[i],args[i+1]);
        return result;
    }
    private static final class Parser {
        final String s; int i=0;
        Parser(String text){s=text;}
        void white(){while(i<s.length() && Character.isWhitespace(s.charAt(i)))i++;}
        char peek(){white();if(i>=s.length())throw error("unexpected end");return s.charAt(i);}
        RuntimeException error(String msg){return new IllegalArgumentException(msg+" at offset "+i);}
        void expect(char c){if(peek()!=c)throw error("expected "+c);i++;}
        Object value(){
            char c=peek();
            if(c=='"')return string();
            if(c=='{')return object();
            if(c=='[')return array();
            if(c=='t')return literal("true",Boolean.TRUE);
            if(c=='f')return literal("false",Boolean.FALSE);
            if(c=='n')return literal("null",null);
            if(c=='-' || (c>='0'&&c<='9'))return number();
            throw error("bad value");
        }
        Object literal(String t,Object v){if(!s.startsWith(t,i))throw error("invalid literal");i+=t.length();return v;}
        Map<String,Object> object(){
            expect('{'); Map<String,Object> m=new LinkedHashMap<>();
            if(peek()=='}'){i++;return m;}
            while(true){if(peek()!='"')throw error("key must be string");String k=string();expect(':');m.put(k,value());char end=peek();if(end=='}'){i++;return m;}expect(',');}
        }
        List<Object> array(){
            expect('[');List<Object> a=new ArrayList<>();
            if(peek()==']'){i++;return a;}
            while(true){a.add(value());if(peek()==']'){i++;return a;}expect(',');}
        }
        String string(){
            expect('"');StringBuilder b=new StringBuilder();
            while(i<s.length()){
                char c=s.charAt(i++);if(c=='"')return b.toString();
                if(c<32)throw error("control char in string");
                if(c=='\\'){
                    if(i>=s.length())throw error("incomplete escape");
                    char esc=s.charAt(i++);
                    switch(esc){case '"'->b.append('"');case '\\'->b.append('\\');case '/'->b.append('/');case 'b'->b.append('\b');case 'f'->b.append('\f');case 'n'->b.append('\n');case 'r'->b.append('\r');case 't'->b.append('\t');
                        case 'u'->{if(i+4>s.length())throw error("bad unicode");try{b.append((char)Integer.parseInt(s.substring(i,i+4),16));}catch(NumberFormatException e){throw error("bad unicode");}i+=4;}
                        default->throw error("unknown escape");
                    }
                }else b.append(c);
            }
            throw error("unterminated string");
        }
        Number number(){
            int start=i; if(s.charAt(i)=='-')i++;
            if(i>=s.length())throw error("bad number");
            if(s.charAt(i)=='0')i++; else {if(s.charAt(i)<'1'||s.charAt(i)>'9')throw error("bad number");while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;}
            boolean fractional=false;
            if(i<s.length()&&s.charAt(i)=='.'){fractional=true;i++;int at=i;while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;if(at==i)throw error("bad decimal");}
            if(i<s.length()&&(s.charAt(i)=='e'||s.charAt(i)=='E')){fractional=true;i++;if(i<s.length()&&(s.charAt(i)=='+'||s.charAt(i)=='-'))i++;int at=i;while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;if(at==i)throw error("bad exponent");}
            String n=s.substring(start,i);return fractional?new BigDecimal(n):new BigInteger(n);
        }
    }
}
