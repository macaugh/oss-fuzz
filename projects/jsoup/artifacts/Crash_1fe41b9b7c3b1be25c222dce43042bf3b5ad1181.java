import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_1fe41b9b7c3b1be25c222dce43042bf3b5ad1181 {
    static final String base64Bytes = String.join("", "PCYjRElWIFNUWUxFPSJ3aWR0aDogZXhwcmVzc2lvbihhbGVydCg3KSkiPgo=");

    public static void main(String[] args) throws Throwable {
        Crash_1fe41b9b7c3b1be25c222dce43042bf3b5ad1181.class.getClassLoader().setDefaultAssertionStatus(true);
        try {
            Method fuzzerInitialize = CleanerWideNetFuzzer.class.getMethod("fuzzerInitialize");
            fuzzerInitialize.invoke(null);
        } catch (NoSuchMethodException ignored) {
            try {
                Method fuzzerInitialize = CleanerWideNetFuzzer.class.getMethod("fuzzerInitialize", String[].class);
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
        CleanerWideNetFuzzer.fuzzerTestOneInput(input);
    }
}