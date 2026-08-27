package toy;

import jakarta.servlet.http.HttpServletResponse;
import java.beans.XMLDecoder;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.regex.Pattern;
import javax.crypto.Cipher;

final class SecurityEffectCases {
    Pattern positiveRegex(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    String positiveStringRegex(String input, String regex, String replacement) {
        return input.replaceAll(regex, replacement);
    }

    Object positiveDeserialization(ObjectInputStream input) throws Exception {
        return input.readObject();
    }

    Object positiveXmlDeserialization(XMLDecoder decoder) {
        return decoder.readObject();
    }

    boolean positiveFilesystem(String path) {
        return new File(path).exists();
    }

    byte[] positiveCrypto(String algorithm, byte[] input)
            throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        Cipher.getInstance(algorithm);
        return digest.digest(input);
    }

    HttpResponse<String> positiveNetwork(
            HttpClient client, HttpRequest request)
            throws IOException, InterruptedException {
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    void positiveRendering(
            HttpServletResponse response, String location, String headerValue) {
        response.sendRedirect(location);
        response.setHeader("X-Test", headerValue);
    }

    void negativeSameNames(String value) {
        FakePattern.compile(value);
        new FakeReader().readObject();
        new FakeClient().send(value);
        new FakeFile().exists();
        FakeCipher.getInstance(value);
        new FakeResponse().sendRedirect(value);
        new FakeResponse().setHeader("X-Test", value);
    }

    static final class FakePattern {
        static void compile(String value) {}
    }

    static final class FakeReader {
        Object readObject() { return null; }
    }

    static final class FakeClient {
        void send(String request) {}
    }

    static final class FakeFile {
        boolean exists() { return false; }
    }

    static final class FakeCipher {
        static void getInstance(String value) {}
    }

    static final class FakeResponse {
        void sendRedirect(String location) {}
        void setHeader(String name, String value) {}
    }
}
