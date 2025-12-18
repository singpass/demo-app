package singpass.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.util.Map;

public class DemoServer {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SessionManager sessions = new SessionManager();
    private static SingpassClient oidcClient;
    private static ConfigLoader config;

    public static void main(String[] args) throws Exception {
        config = new ConfigLoader("../config.json");
        oidcClient = new SingpassClient(config);

        HttpServer server = HttpServer.create(new InetSocketAddress(config.serverPort), 0);

        server.createContext("/", ex -> handleRequest(ex, DemoServer::serveStatic));
        server.createContext("/.well-known/jwks.json", ex -> handleRequest(ex, DemoServer::handleJwks));
        server.createContext("/login", ex -> handleRequest(ex, DemoServer::handleLogin));
        server.createContext("/callback", ex -> handleRequest(ex, DemoServer::handleCallback));
        server.createContext("/user", ex -> handleRequest(ex, DemoServer::handleUser));
        server.createContext("/logout", ex -> handleRequest(ex, DemoServer::handleLogout));

        server.setExecutor(null);
        server.start();

        System.out.println("Server running on http://localhost:" + config.serverPort);
    }

    private static void handleRequest(HttpExchange ex, Handler handler) {
        try {
            handler.handle(ex);
        } catch (Exception e) {
            e.printStackTrace();
            try {
                sendResponse(ex, 500, "Internal Server Error: " + e.getMessage());
            } catch (Exception ignored) {
            }
        }
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange ex) throws Exception;
    }

    private static void serveStatic(HttpExchange ex) throws Exception {
        String path = ex.getRequestURI().getPath();
        if (path.equals("/"))
            path = "/index.html";

        File file = new File("../frontend" + path);
        if (!file.exists() || file.isDirectory()) {
            sendResponse(ex, 404, "Not Found");
            return;
        }

        String contentType = path.endsWith(".html") ? "text/html"
                : path.endsWith(".css") ? "text/css" : path.endsWith(".svg") ? "image/svg+xml" : "text/plain";

        byte[] content = Files.readAllBytes(file.toPath());
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(200, content.length);
        ex.getResponseBody().write(content);
        ex.close();
    }

    private static void handleJwks(HttpExchange ex) throws Exception {
        Map<String, Object> jwks = Map.of("keys",
                java.util.List.of(config.publicSigningKey.toJSONObject(),
                        config.publicEncryptionKey.toJSONObject()));
        sendJson(ex, 200, jwks);
    }

    private static void handleLogin(HttpExchange ex) throws Exception {
        oidcClient.refreshIfNeeded();

        String sessionId = getOrCreateSession(ex);
        SessionManager.SessionData session = sessions.retrieve(sessionId);

        if (session == null) {
            clearSessionAndRedirect(ex);
            return;
        }

        SessionManager.AuthState auth = new SessionManager.AuthState();
        auth.codeVerifier = new CodeVerifier();
        auth.nonceValue = new Nonce();
        auth.stateValue = new State();
        auth.dpopKeyPair = oidcClient.generateDPoPKey();
        session.auth = auth;

        URI redirectUri = oidcClient.buildAuthUrl(auth.codeVerifier, auth.nonceValue, auth.stateValue,
                auth.dpopKeyPair);

        ex.getResponseHeaders().set("Location", redirectUri.toString());
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    private static void handleCallback(HttpExchange ex) throws Exception {
        try {
            String sessionId = extractSessionId(ex);
            SessionManager.SessionData session = sessions.retrieve(sessionId);

            if (session == null || session.auth == null) {
                sendResponse(ex, 401, "No session");
                return;
            }

            AuthorizationCode code = oidcClient.getAuthCodeFromCallback(
                    ex.getRequestURI(),
                    session.auth.stateValue);
            Map<String, Object> userData = oidcClient.exchangeCode(
                    code,
                    session.auth.codeVerifier,
                    session.auth.nonceValue,
                    session.auth.stateValue,
                    config.redirectUri,
                    session.auth.dpopKeyPair);

            session.userData = userData;
            session.auth = null;

            ex.getResponseHeaders().set("Location", "/");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(ex, 401, "Authentication failed");
        }
    }

    private static void handleUser(HttpExchange ex) throws Exception {
        String sessionId = extractSessionId(ex);

        if (sessionId != null) {
            SessionManager.SessionData session = sessions.retrieve(sessionId);

            if (session == null) {
                clearSessionAndRedirect(ex);
                return;
            }

            if (session.userData != null) {
                sendJson(ex, 200, session.userData);
                return;
            }
        }

        ex.sendResponseHeaders(401, -1);
        ex.close();
    }

    private static void handleLogout(HttpExchange ex) throws Exception {
        String sessionId = extractSessionId(ex);
        sessions.clear(sessionId);

        clearSessionAndRedirect(ex);
    }

    private static String getOrCreateSession(HttpExchange ex) {
        String sessionId = extractSessionId(ex);
        if (sessionId == null || sessions.retrieve(sessionId) == null) {
            sessionId = sessions.newSession();
            ex.getResponseHeaders().set("Set-Cookie", "sessionId=" + sessionId + "; Path=/");
        }
        return sessionId;
    }

    private static void clearSessionAndRedirect(HttpExchange ex) throws Exception {
        ex.getResponseHeaders().set("Set-Cookie", "sessionId=; Max-Age=0; Path=/");
        ex.getResponseHeaders().set("Location", "/");
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    private static String extractSessionId(HttpExchange ex) {
        String cookie = ex.getRequestHeaders().getFirst("Cookie");
        if (cookie != null) {
            for (String part : cookie.split(";")) {
                String[] kv = part.trim().split("=", 2);
                if (kv.length == 2 && kv[0].equals("sessionId")) {
                    return kv[1];
                }
            }
        }
        return null;
    }

    private static void sendJson(HttpExchange ex, int status, Object data) throws Exception {
        byte[] response = JSON.writeValueAsBytes(data);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, response.length);
        ex.getResponseBody().write(response);
        ex.close();
    }

    private static void sendResponse(HttpExchange ex, int status, String message) throws Exception {
        byte[] response = message.getBytes();
        ex.sendResponseHeaders(status, response.length);
        ex.getResponseBody().write(response);
        ex.close();
    }
}