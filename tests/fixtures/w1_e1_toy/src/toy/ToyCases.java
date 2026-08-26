package toy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.RequestParam;

public final class ToyCases {
    private ToyCases() {}

    // Toy A: the discovered input is data-connected to the discovered effect.
    public static byte[] connected(@RequestParam Path requestPath) throws IOException {
        return Files.readAllBytes(identity(requestPath));
    }

    // Toy B: input and effect coexist, but there is deliberately no data path.
    public static byte[] disconnected(@RequestParam Path unusedPath) throws IOException {
        Path fixedPath = Path.of("fixed.txt");
        return Files.readAllBytes(fixedPath);
    }

    // Toy C: forward and backward regions share a method but remain disconnected.
    public static byte[] structural(@RequestParam Path requestPath) throws IOException {
        Path forwardOnly = identity(requestPath);
        observe(forwardOnly);
        Path backwardOnly = Path.of("fixed.txt");
        return Files.readAllBytes(identity(backwardOnly));
    }

    private static Path identity(Path value) {
        return value;
    }

    private static void observe(Path ignored) {}
}
