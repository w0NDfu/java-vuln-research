package com.example;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.file.Files;
import java.nio.file.Path;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.PARAMETER})
@interface BoundValue {}

interface ValueCallback {
    void onValue(String value);
}

public class ControlledSecurityCases {
    private String state;
    private String secondaryState;
    private String tokenState;
    private String pathState;
    private String messageState;

    public String customExternalInput(String raw) {
        return wrap(raw);
    }

    public void customSecurityEffect(String path) throws Exception {
        Files.writeString(Path.of(path), "controlled");
    }

    public String wrap(String input) {
        return input;
    }

    public void setState(String value) {
        this.state = value;
    }

    public String getState() {
        return this.state;
    }

    public void setSecondaryState(String value) { this.secondaryState = value; }
    public String getSecondaryState() { return this.secondaryState; }
    public void setTokenState(String value) { this.tokenState = value; }
    public String getTokenState() { return this.tokenState; }
    public void setPathState(String value) { this.pathState = value; }
    public String getPathState() { return this.pathState; }
    public void setMessageState(String value) { this.messageState = value; }
    public String getMessageState() { return this.messageState; }

    public void register(ValueCallback callback) {
        callback.onValue(state);
    }

    public void trigger(ValueCallback callback, String value) {
        callback.onValue(value);
    }

    @BoundValue
    public void frameworkBound(@BoundValue String value) {
        setState(value);
    }

    static class AlternateState {
        private String state;
    }
}
