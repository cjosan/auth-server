package com.cjosan.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

	private final AuthenticationManager authenticationManager;

	private final DataSource dataSource;
	private final PasswordEncoder passwordEncoder;

	public AuthServerConfig(AuthenticationManager authenticationManager, DataSource dataSource, PasswordEncoder passwordEncoder) {
		this.authenticationManager = authenticationManager;
		this.dataSource = dataSource;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints.authenticationManager(authenticationManager)
				.tokenStore(tokenStore())
				.accessTokenConverter(converter());
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) {
		security.tokenKeyAccess("isAuthenticated()");
	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(converter());
	}

	@Bean
	public JwtAccessTokenConverter converter() {
		var conv = new JwtAccessTokenConverter();


		// TODO use a vault or another secure method to retrieve the key
		KeyStoreKeyFactory keyFactory = new KeyStoreKeyFactory(
				new ClassPathResource("ssia.jks"),
				"ssia123".toCharArray()
		);

		conv.setKeyPair(keyFactory.getKeyPair("ssia"));

		return conv;
	}
}
