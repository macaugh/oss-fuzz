import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_eb707154b83afa77e9a90436b4cde19d72ba3622 {
    static final String base64Bytes = String.join("", "PFM+CTxmcmFtZXNldC8+PC9mcmFtZXNldD5SCWNoYXJzZXQ9cwAAPj88CTwvZnJhbWVzZXQ+Uv//P3N2Zyt4bD4/CTwvZnJhbWVzZXQ+c3ZtbD4/");

    public static void main(String[] args) throws Throwable {
        Crash_eb707154b83afa77e9a90436b4cde19d72ba3622.class.getClassLoader().setDefaultAssertionStatus(true);
        try {
            Method fuzzerInitialize = CleanerDomPrecisionFuzzer.class.getMethod("fuzzerInitialize");
            fuzzerInitialize.invoke(null);
        } catch (NoSuchMethodException ignored) {
            try {
                Method fuzzerInitialize = CleanerDomPrecisionFuzzer.class.getMethod("fuzzerInitialize", String[].class);
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
        CleanerDomPrecisionFuzzer.fuzzerTestOneInput(input);
    }
}