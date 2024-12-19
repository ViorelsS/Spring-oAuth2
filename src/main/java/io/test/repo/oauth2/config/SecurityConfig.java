package io.test.repo.oauth2.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.test.repo.oauth2.config.jwtConfig.JwtAccessTokenFilter;
import io.test.repo.oauth2.config.jwtConfig.JwtRefreshTokenFilter;
import io.test.repo.oauth2.config.jwtConfig.JwtTokenUtils;
import io.test.repo.oauth2.config.userConfig.UserInfoManagerConfig;
import io.test.repo.oauth2.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

	Logger log = LoggerFactory.getLogger(SecurityConfig.class);

	private final UserInfoManagerConfig userInfoManagerConfig;
	private final RSAKeyRecord rsaKeyRecord;
	private final JwtTokenUtils jwtTokenUtils;
	private final RefreshTokenRepository refreshTokenRepo;

	public SecurityConfig(UserInfoManagerConfig userInfoManagerConfig, RSAKeyRecord rsaKeyRecord,
			JwtTokenUtils jwtTokenUtils, RefreshTokenRepository refreshTokenRepo) {
		this.userInfoManagerConfig = userInfoManagerConfig;
		this.rsaKeyRecord = rsaKeyRecord;
		this.jwtTokenUtils = jwtTokenUtils;
		this.refreshTokenRepo = refreshTokenRepo;
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
	}

	@Bean
	JwtEncoder jwtEncoder() {
		JWK jwk = new RSAKey.Builder(rsaKeyRecord.rsaPublicKey()).privateKey(rsaKeyRecord.rsaPrivateKey()).build();
		JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwkSource);
	}

	@Order(1)
	@Bean
	public SecurityFilterChain signInSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.securityMatcher(new AntPathRequestMatcher("/sign-in/**")).csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).userDetailsService(userInfoManagerConfig)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				//STATELESS -> per ogni req c'è bisogno di fare l'autenticazione (non storiamo da nessuna parte le info)
				.formLogin(withDefaults()).exceptionHandling(ex -> {
					ex.authenticationEntryPoint(
							(request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
									authException.getMessage()));
				}).httpBasic(withDefaults()).build();
	}

	@Order(2)
	@Bean
	public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.securityMatcher(new AntPathRequestMatcher("/api/**")).csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils),
						UsernamePasswordAuthenticationFilter.class).exceptionHandling(ex -> {
					log.error("[SecurityConfig:apiSecurityFilterChain] Exception due to :{}", ex);
					ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
					ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
				}).httpBasic(withDefaults()).build();
	}

	@Order(2)
	@Bean
	public SecurityFilterChain h2ConsoleSecurityFilterChainConfig(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.securityMatcher(new AntPathRequestMatcher(("/h2-console/**")))
				.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				.csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
				.headers(headers -> headers.frameOptions(withDefaults()).disable()).build();
	}

	@Order(3)
	@Bean
	public SecurityFilterChain refreshTokenSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.securityMatcher(new AntPathRequestMatcher("/refresh-token/**"))
				.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.addFilterBefore(new JwtRefreshTokenFilter(rsaKeyRecord, jwtTokenUtils, refreshTokenRepo),
						UsernamePasswordAuthenticationFilter.class).exceptionHandling(ex -> {
					log.error("[SecurityConfig:refreshTokenSecurityFilterChain] Exception due to :{}", ex);
					ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
					ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
				}).httpBasic(withDefaults()).build();
	}

}
