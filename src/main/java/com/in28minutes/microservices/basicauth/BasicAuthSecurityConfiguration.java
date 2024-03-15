package com.in28minutes.microservices.basicauth;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
public class BasicAuthSecurityConfiguration {
	
	@Bean
	SecurityFilterChain  securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests(auth->{
			auth.anyRequest().authenticated();
			
		});
		http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.httpBasic();																					
		http.csrf().disable();
		http.headers().frameOptions().sameOrigin();
		return http.build();
	}
	
//	@Bean
//	public UserDetailsService userDetailsService() {
//		var user = User.withUsername("user")
//				.password("{noop}user")
//				.roles("ADMIN")
//				.build()
//			;
//		
//		var admin = User.withUsername("admin")
//				.password("{noop}admin")
//				.roles("USER")
//				.build()
//			;
//		return new InMemoryUserDetailsManager(user, admin);
//		
//	}
	
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
//				.password("{noop}admin")
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
	
//	@Bean 
//	public WebMvcConfigurer corsConfigurer() {
//		return new WebMvcConfigurer() {
//			
//			public void addCorsMappings(CorsRegistry registry)
//			{
//				registry.addMapping("/**").allowedMethods("*").allowedOrigins("*");
//			}
//		}; 
//	}
}
 