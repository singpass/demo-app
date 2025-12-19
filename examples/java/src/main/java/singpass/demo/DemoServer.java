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

        server.createContext("/", httpExchange -> handleRequest(httpExchange, DemoServer::serveStatic));
        server.createContext("/.well-known/jwks.json",
                httpExchange -> handleRequest(httpExchange, DemoServer::handleJwks));
        server.createContext("/login", httpExchange -> handleRequest(httpExchange, DemoServer::handleLogin));
        server.createContext("/callback", httpExchange -> handleRequest(httpExchange, DemoServer::handleCallback));
        server.createContext("/user", httpExchange -> handleRequest(httpExchange, DemoServer::handleUser));
        server.createContext("/logout", httpExchange -> handleRequest(httpExchange, DemoServer::handleLogout));

        server.setExecutor(null);
        server.start();

        System.out.println("Server running on http://localhost:" + config.serverPort);
    }

    private static void handleRequest(HttpExchange httpExchange, Handler handler) {
        try {
            handler.handle(httpExchange);
        } catch (Exception e) {
            e.printStackTrace();
            try {
                sendResponse(httpExchange, 500, "Internal Server Error: " + e.getMessage());
            } catch (Exception ignored) {
            }
        }
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange httpExchange) throws Exception;
    }

    private static void serveStatic(HttpExchange httpExchange) throws Exception {
        String path = httpExchange.getRequestURI().getPath();
        if (path.equals("/"))
            path = "/index.html";

        File file = new File("../frontend" + path);
        if (!file.exists() || file.isDirectory()) {
            sendResponse(httpExchange, 404, "Not Found");
            return;
        }

        String contentType = path.endsWith(".html") ? "text/html"
                : path.endsWith(".css") ? "text/css" : path.endsWith(".svg") ? "image/svg+xml" : "text/plain";

        byte[] content = Files.readAllBytes(file.toPath());
        httpExchange.getResponseHeaders().set("Content-Type", contentType);
        httpExchange.sendResponseHeaders(200, content.length);
        httpExchange.getResponseBody().write(content);
        httpExchange.close();
    }

    private static void handleJwks(HttpExchange httpExchange) throws Exception {
        Map<String, Object> jwks = Map.of("keys",
                java.util.List.of(config.publicSigningKey.toJSONObject(),
                        config.publicEncryptionKey.toJSONObject()));
        sendJson(httpExchange, 200, jwks);
    }

    private static void handleLogin(HttpExchange httpExchange) throws Exception {
        oidcClient.refreshIfNeeded();

        String sessionId = getOrCreateSession(httpExchange);
        SessionManager.SessionData session = sessions.retrieve(sessionId);

        if (session == null) {
            clearSessionAndRedirect(httpExchange);
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

        httpExchange.getResponseHeaders().set("Location", redirectUri.toString());
        httpExchange.sendResponseHeaders(302, -1);
        httpExchange.close();
    }

    private static void handleCallback(HttpExchange httpExchange) throws Exception {
        try {
            String sessionId = extractSessionId(httpExchange);
            SessionManager.SessionData session = sessions.retrieve(sessionId);

            if (session == null || session.auth == null) {
                sendResponse(httpExchange, 401, "No session");
                return;
            }

            AuthorizationCode code = oidcClient.getAuthCodeFromCallback(
                    httpExchange.getRequestURI(),
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

            httpExchange.getResponseHeaders().set("Location", "/");
            httpExchange.sendResponseHeaders(302, -1);
            httpExchange.close();
        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(httpExchange, 401, "Authentication failed");
        }
    }

    private static void handleUser(HttpExchange httpExchange) throws Exception {
        String sessionId = extractSessionId(httpExchange);

        if (sessionId != null) {
            SessionManager.SessionData session = sessions.retrieve(sessionId);

            if (session == null) {
                clearSessionAndRedirect(httpExchange);
                return;
            }

            if (session.userData != null) {
                sendJson(httpExchange, 200, session.userData);
                return;
            }
        }

        httpExchange.sendResponseHeaders(401, -1);
        httpExchange.close();
    }

    private static void handleLogout(HttpExchange httpExchange) throws Exception {
        String sessionId = extractSessionId(httpExchange);
        sessions.clear(sessionId);

        clearSessionAndRedirect(httpExchange);
    }

    private static String getOrCreateSession(HttpExchange httpExchange) {
        String sessionId = extractSessionId(httpExchange);
        if (sessionId == null || sessions.retrieve(sessionId) == null) {
            sessionId = sessions.newSession();
            httpExchange.getResponseHeaders().set("Set-Cookie", "sessionId=" + sessionId + "; Path=/");
        }
        return sessionId;
    }

    private static void clearSessionAndRedirect(HttpExchange httpExchange) throws Exception {
        httpExchange.getResponseHeaders().set("Set-Cookie", "sessionId=; Max-Age=0; Path=/");
        httpExchange.getResponseHeaders().set("Location", "/");
        httpExchange.sendResponseHeaders(302, -1);
        httpExchange.close();
    }

    private static String extractSessionId(HttpExchange httpExchange) {
        String cookie = httpExchange.getRequestHeaders().getFirst("Cookie");
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

    private static void sendJson(HttpExchange httpExchange, int status, Object data) throws Exception {
        byte[] response = JSON.writeValueAsBytes(data);
        httpExchange.getResponseHeaders().set("Content-Type", "application/json");
        httpExchange.sendResponseHeaders(status, response.length);
        httpExchange.getResponseBody().write(response);
        httpExchange.close();
    }

    private static void sendResponse(HttpExchange httpExchange, int status, String message) throws Exception {
        byte[] response = message.getBytes();
        httpExchange.sendResponseHeaders(status, response.length);
        httpExchange.getResponseBody().write(response);
        httpExchange.close();
    }
}