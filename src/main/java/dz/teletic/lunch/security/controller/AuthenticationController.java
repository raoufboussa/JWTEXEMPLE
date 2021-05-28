package dz.teletic.lunch.security.controller;

import dz.teletic.lunch.model.User;
import dz.teletic.lunch.security.auth.JwtAuthenticationRequest;
import dz.teletic.lunch.security.auth.TokenHelper;
import dz.teletic.lunch.security.dto.PasswordChangerDto;
import dz.teletic.lunch.security.dto.TokenDto;
import dz.teletic.lunch.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping(value = "/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final TokenHelper tokenHelper;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    @PostMapping(value = "/login")
    public ResponseEntity<?> generateToken(@RequestBody JwtAuthenticationRequest authenticationRequest,
                                           HttpServletResponse response) {
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
                        authenticationRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();

        List<String> roles = user.getRoles().stream()
                .map(role -> role.getRole().name())
                .collect(Collectors.toList());

        boolean isPasswordChanged = userService.isPasswordChanged(user);

        String token = tokenHelper.generateToken(user.getUsername(), roles, isPasswordChanged,
                user.getFirstName() + " " + user.getLastName(), user.getEmail());
        long expiresIn = tokenHelper.getExpiredIn();

        return ResponseEntity.ok(new TokenDto(token, expiresIn));
    }

    @PostMapping(value = "/refresh-token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        Optional<String> authToken = tokenHelper.getToken(request);

        if (!authToken.isPresent()) {
            throw new RuntimeException("Full authentication is required to access this resource");
        }

        if (tokenHelper.isTokenRefreshable(authToken.get())) {
            String refreshedToken = tokenHelper.refreshToken(authToken.get());
            long expiresIn = tokenHelper.getExpiredIn();

            return ResponseEntity.ok(new TokenDto(refreshedToken, expiresIn));
        } else {
            throw new RuntimeException(String.format("Token not acceptable for refresh {Token %s}", authToken.get()));
        }
    }

    @PostMapping(value = "/change-password")
    public ResponseEntity<Void> changePassword(@RequestBody PasswordChangerDto passwordChangerDto) {
        userService.changePassword(passwordChangerDto.getCurrentPassword(), passwordChangerDto.getNewPassword());

        return ResponseEntity.ok().build();
    }

}
