package jakarta.servlet.http;

public interface HttpServletResponse {
    void sendRedirect(String location);
    void setHeader(String name, String value);
}
