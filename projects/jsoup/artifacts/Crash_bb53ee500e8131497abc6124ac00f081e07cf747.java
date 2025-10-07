import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_bb53ee500e8131497abc6124ac00f081e07cf747 {
    static final String base64Bytes = String.join("", "PO+8nHNjcmlwdD5hbGVydCgxMCnvvJ4vc3htbCw8c3ZnIHhtbG5zPWh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIG9ubG9hZD1hbGVydCgyKT4K");

    public static void main(String[] args) throws Throwable {
        Crash_bb53ee500e8131497abc6124ac00f081e07cf747.class.getClassLoader().setDefaultAssertionStatus(true);
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