package br.com.atividade.seguranca.repositories;

import br.com.atividade.seguranca.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;

@Repository
public class UserRepository {
    private final Map<String, User> users;

    public UserRepository(PasswordEncoder passwordEncoder) {
        User testUser = new User(
                "teste@email.com",
                passwordEncoder.encode("123456"),
                "Usuário",
                "de Teste"
        );
        this.users = Map.of(testUser.getEmail(), testUser);
    }

    public Optional<User> findByEmail(String email) {
        return Optional.ofNullable(users.get(email));
    }
}
