package singpass.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.id.ClientID;

import java.io.File;
import java.net.URI;

public class ConfigLoader {
    public final int serverPort;
    public final ClientID clientId;
    public final URI issuerUrl;
    public final URI redirectUri;
    public final String scopes;
    public final ECKey privateSigningKey;
    public final ECKey privateEncryptionKey;
    public final ECKey publicSigningKey;
    public final ECKey publicEncryptionKey;

    public ConfigLoader(String path) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(new File(path));

        this.serverPort = root.get("SERVER_PORT").asInt();
        this.clientId = new ClientID(root.get("CLIENT_ID").asText());
        this.issuerUrl = new URI(root.get("ISSUER_URL").asText());
        this.redirectUri = new URI(root.get("REDIRECT_URI").asText());
        this.scopes = root.get("SCOPES").asText();

        JsonNode keys = root.get("KEYS");
        this.privateSigningKey = ECKey.parse(keys.get("PRIVATE_SIG_KEY").toString());
        this.privateEncryptionKey = ECKey.parse(keys.get("PRIVATE_ENC_KEY").toString());
        this.publicSigningKey = ECKey.parse(keys.get("PUBLIC_SIG_KEY").toString());
        this.publicEncryptionKey = ECKey.parse(keys.get("PUBLIC_ENC_KEY").toString());
    }
}