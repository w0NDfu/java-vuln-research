package controlled.m8;

import java.nio.file.Files;
import java.nio.file.Path;

public class ControlledRequestPipeline {
    @RequestBoundary
    public void receive(String requestPath) throws Exception {
        persist(carry(requestPath));
    }

    private String carry(String value) {
        return value;
    }

    private void persist(String path) throws Exception {
        Files.writeString(Path.of(path), "controlled");
    }

    public String benignConstant() {
        return "fixed";
    }
}

@interface RequestBoundary {
}
