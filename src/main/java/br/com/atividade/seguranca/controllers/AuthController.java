package br.com.atividade.seguranca.controllers;

import br.com.atividade.seguranca.auth.JwtUtil;
import br.com.atividade.seguranca.model.User;
import br.com.atividade.seguranca.model.request.LoginReq;
import br.com.atividade.seguranca.model.response.ErrorRes;
import br.com.atividade.seguranca.model.response.LoginRes;
import br.com.atividade.seguranca.repositories.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public AuthController(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            JwtUtil jwtUtil
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq loginReq) {
        if (loginReq.getEmail() == null || loginReq.getEmail().isBlank()
                || loginReq.getPassword() == null || loginReq.getPassword().isBlank()) {
            return ResponseEntity.badRequest()
                    .body(new ErrorRes("E-mail e senha são obrigatórios", HttpStatus.BAD_REQUEST.value()));
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginReq.getEmail(), loginReq.getPassword())
            );
            User user = userRepository.findByEmail(loginReq.getEmail())
                    .orElseThrow(() -> new BadCredentialsException("Credenciais inválidas"));
            return ResponseEntity.ok(new LoginRes(user.getEmail(), jwtUtil.generateToken(user)));
        } catch (BadCredentialsException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorRes("E-mail ou senha inválidos", HttpStatus.UNAUTHORIZED.value()));
        }
    }
}
