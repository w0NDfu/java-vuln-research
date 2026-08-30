package com.example;

import java.nio.file.Files;
import java.nio.file.Path;

public class ControlledSecurityCases {
    public String customExternalInput(String raw) {
        return raw;
    }

    public void customSecurityEffect(String path) throws Exception {
        Files.writeString(Path.of(path), "controlled");
    }

    public void controlledPipeline(String raw) throws Exception {
        String value = customExternalInput(raw);
        customSecurityEffect(value);
    }
}
