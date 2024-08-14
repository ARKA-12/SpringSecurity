package codeme.com.spring_security_jwt.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import codeme.com.spring_security_jwt.config.JwtService;
import codeme.com.spring_security_jwt.user.Role;
import codeme.com.spring_security_jwt.user.User;
import codeme.com.spring_security_jwt.user.User.UserBuilder;
import codeme.com.spring_security_jwt.user.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;

    public AuthenticationResponse register(RegisterRequest request){
       var user = ((UserBuilder) User
       .builder()
       .firstname(request.getFirstname()))
       .lastname(request.getLastname())
       .email(request.getEmail())
       .password(passwordEncoder.encode(request.getPassword()))
       .role(Role.USER)
       .build();

       userRepository.save(user);

       var jwtToken = jwtService.generateToken(user);
       return AuthenticationResponse.builder().token(jwtToken).build();

    }
public AuthenticationResponse authenticate(AuthenticationRequest request){

    
    return null;
}



}
