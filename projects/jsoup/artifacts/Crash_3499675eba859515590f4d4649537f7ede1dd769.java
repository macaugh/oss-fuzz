import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_3499675eba859515590f4d4649537f7ede1dd769 {
    static final String base64Bytes = String.join("", "PElNRyBTUkM9Imh0dHA6dUM8c2NyaXB0NCkiPjw=");

    public static void main(String[] args) throws Throwable {
        Crash_3499675eba859515590f4d4649537f7ede1dd769.class.getClassLoader().setDefaultAssertionStatus(true);
        try {
            Method fuzzerInitialize = CleanerDomPrecisionFuzzerSimple.class.getMethod("fuzzerInitialize");
            fuzzerInitialize.invoke(null);
        } catch (NoSuchMethodException ignored) {
            try {
                Method fuzzerInitialize = CleanerDomPrecisionFuzzerSimple.class.getMethod("fuzzerInitialize", String[].class);
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
        CleanerDomPrecisionFuzzerSimple.fuzzerTestOneInput(input);
    }
}