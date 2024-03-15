package com.in28minutes.microservices.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JWTSecurityConfiguration {
	
	@Bean
	SecurityFilterChain  securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests(auth->{
			auth.anyRequest().authenticated();
			
		});
		http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.httpBasic();																					
		http.csrf().disable();
		http.headers().frameOptions().sameOrigin();
		
		//org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer.jwt();
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}
	
	@Bean
	public KeyPair keyPair()
	{
		try {
			KeyPairGenerator keyPairGenerator =  KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} 
		catch (NoSuchAlgorithmException e) {
			
			throw new RuntimeException(e);
		}
	}
	
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey(keyPair.getPrivate())
			.keyID(UUID.randomUUID().toString())
			.build()
			;
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey)
	{
		var jwkSet = new JWKSet(rsaKey);
		
		return (jwkSelector,context)-> jwkSelector.select(jwkSet);
	}
	
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws Exception {
		
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
		
	}
	
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		var user = User.withUsername("user")
				//.password("{noop}user")
				.password("user")
				.passwordEncoder(pass-> passEncoder().encode(pass))
				.roles("USER")
				.build()
			;
		
		var admin = User.withUsername("admin")
				.password("admin")
				.passwordEncoder(pass-> passEncoder().encode(pass))
				.roles("USER","ADMIN")
				.build()
			;
		var users = new JdbcUserDetailsManager(dataSource);
		users.createUser(admin);
		users.createUser(user);
		return users;
		
	}
	
	@Bean
	public DataSource dataSource() {
	return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
			.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
			.build();	
	}
	
	@Bean
	public BCryptPasswordEncoder passEncoder()
	{
		return new BCryptPasswordEncoder();
	}
	
}
 