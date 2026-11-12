package br.com.atividade.seguranca;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "app.jwt.secret=integration-test-signing-key-must-be-at-least-32-bytes",
        "app.jwt.expiration-ms=3600000"
})
class AuthenticationIntegrationTest {
    private static final String TEST_SECRET = "integration-test-signing-key-must-be-at-least-32-bytes";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void loginWithCorrectCredentialsReturnsEmailAndJwt() throws Exception {
        String response = mockMvc.perform(post("/rest/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"teste@email.com","password":"123456"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("teste@email.com"))
                .andExpect(jsonPath("$.token", startsWith("eyJ")))
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode body = objectMapper.readTree(response);
        String token = body.get("token").asText();
        mockMvc.perform(get("/rest/home").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("hello world"));
    }

    @Test
    void loginWithIncorrectCredentialsReturnsUnauthorized() throws Exception {
        mockMvc.perform(post("/rest/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"teste@email.com","password":"senha-incorreta"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("E-mail ou senha inválidos"));
    }

    @Test
    void protectedHomeRejectsMissingToken() throws Exception {
        mockMvc.perform(get("/rest/home"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedHomeRejectsInvalidToken() throws Exception {
        mockMvc.perform(get("/rest/home").header("Authorization", "Bearer token-invalido"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Token JWT inválido ou expirado"));
    }

    @Test
    void protectedHomeRejectsExpiredToken() throws Exception {
        SecretKey key = Keys.hmacShaKeyFor(TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();
        String expiredToken = Jwts.builder()
                .subject("teste@email.com")
                .issuedAt(Date.from(now.minusSeconds(120)))
                .expiration(Date.from(now.minusSeconds(60)))
                .signWith(key)
                .compact();

        mockMvc.perform(get("/rest/home").header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Token JWT inválido ou expirado"));
    }
}
