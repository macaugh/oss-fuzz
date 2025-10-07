import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_223ca94006b2674a223b49444f45920fb8db7756 {
    static final String base64Bytes = String.join("", "PGEgaHJlZj0iamF2YXNjcmlwdCZhbXA7Y29sb247YWxlcnQoMSkiPng8L2E+Cg==");

    public static void main(String[] args) throws Throwable {
        Crash_223ca94006b2674a223b49444f45920fb8db7756.class.getClassLoader().setDefaultAssertionStatus(true);
        try {
            Method fuzzerInitialize = CleanerWideNetRelativeLinksFuzzerV2.class.getMethod("fuzzerInitialize");
            fuzzerInitialize.invoke(null);
        } catch (NoSuchMethodException ignored) {
            try {
                Method fuzzerInitialize = CleanerWideNetRelativeLinksFuzzerV2.class.getMethod("fuzzerInitialize", String[].class);
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
        CleanerWideNetRelativeLinksFuzzerV2.fuzzerTestOneInput(input);
    }
}