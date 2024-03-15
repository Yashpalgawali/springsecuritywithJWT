package com.in28minutes.microservices.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtAuthenticationResource {

	//@Autowired
	private JwtEncoder jwtEncoder;
	
	public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}
	
	@PostMapping("/authenticate")
	public JwtResponse authenticate(Authentication authentication) {
		
		return new JwtResponse(createToken(authentication));
	}

	private String createToken(Authentication authentication) {
		
		JwtClaimsSet.builder().issuer("self")
		.issuedAt(Instant.now())
		.expiresAt(Instant.now().plusSeconds(60*30))
		.subject(authentication.getName())
		.claim("scope", createScope(authentication))
		.build();
		return null;
	}

	private String createScope(Authentication authentication) {
		return authentication.getAuthorities().stream().map(a->a.getAuthority()).collect(Collectors.joining(" "));
		
	}
}

record JwtResponse(String token) { } 