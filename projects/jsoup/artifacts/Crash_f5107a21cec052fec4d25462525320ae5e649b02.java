import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_f5107a21cec052fec4d25462525320ae5e649b02 {
    static final String base64Bytes = String.join("", "PGEgaHJlZj0iL2phdmFzY3JpcHQ6YWxlcnQoMSkiPng8L2E+Cg==");

    public static void main(String[] args) throws Throwable {
        Crash_f5107a21cec052fec4d25462525320ae5e649b02.class.getClassLoader().setDefaultAssertionStatus(true);
        try {
            Method fuzzerInitialize = CleanerWideNetRelativeLinksFuzzer.class.getMethod("fuzzerInitialize");
            fuzzerInitialize.invoke(null);
        } catch (NoSuchMethodException ignored) {
            try {
                Method fuzzerInitialize = CleanerWideNetRelativeLinksFuzzer.class.getMethod("fuzzerInitialize", String[].class);
                fuzzerInitialize.invoke(null, (Object) args);
            } catch (NoSuchMethodException ignored1) {
            } catch (IllegalAccessException | InvocationTargetException e) {
                e.printStackTrace();
                System.exit(1);
            }
        } catch (IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
            System.exit(1);
        }
        byte[] input = java.util.Base64.getDecoder().decode(base64Bytes);
        CleanerWideNetRelativeLinksFuzzer.fuzzerTestOneInput(input);
    }
}