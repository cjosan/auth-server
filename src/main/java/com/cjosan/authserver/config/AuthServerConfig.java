package com.cjosan.authserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	public AuthenticationManager authenticationManager;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		// TODO use database instead of in memory clients
		clients.inMemory()
				.withClient("client1")
				.secret("secret1")
				.authorizedGrantTypes("password") // TODO use another grant type
				.scopes("read");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager)
				.tokenStore(tokenStore())
				.accessTokenConverter(converter());
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
