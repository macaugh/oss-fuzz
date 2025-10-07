package harnesses;

import java.nio.file.Files;
import java.nio.file.Paths;

public class RunConnectRepro {
  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("Usage: java -cp .:jsoup.jar:../jazzer/jazzer_standalone.jar harnesses.RunConnectRepro <input_file>");
      System.exit(2);
    }
    byte[] in = Files.readAllBytes(Paths.get(args[0]));
    try {
      JsoupConnectFuzzer.fuzzerInitialize();
    } catch (Throwable ignored) {}
    System.out.println("[Repro] Running fuzzerTestOneInput on " + args[0] + " (" + in.length + " bytes)");
    try {
      JsoupConnectFuzzer.fuzzerTestOneInput(in);
      System.out.println("[Repro] Completed without uncaught exception.");
    } catch (Throwable t) {
      System.out.println("[Repro] Uncaught: " + t.getClass().getName() + ": " + t.getMessage());
      t.printStackTrace(System.out);
    }
  }
}

