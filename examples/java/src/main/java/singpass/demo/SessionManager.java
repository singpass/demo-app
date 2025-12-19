package singpass.demo;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

// for demo purposes, we use a simple in-memory session store
public class SessionManager {
    private final Map<String, SessionData> store = new ConcurrentHashMap<>();

    public static class SessionData {
        public AuthState auth;
        public Map<String, Object> userData;
    }

    public static class AuthState {
        public CodeVerifier codeVerifier;
        public Nonce nonceValue;
        public State stateValue;
        public ECKey dpopKeyPair;
    }

    public String newSession() {
        String id = UUID.randomUUID().toString();
        System.out.println("Created session: " + id);
        store.put(id, new SessionData());
        return id;
    }

    public SessionData retrieve(String id) {
        return id != null ? store.get(id) : null;
    }

    public void clear(String id) {
        if (id != null) {
            store.remove(id);
        }
    }
}