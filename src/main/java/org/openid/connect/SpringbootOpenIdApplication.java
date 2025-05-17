package org.openid.connect;

import org.openid.connect.config.OidcConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import(OidcConfig.class)
public class SpringbootOpenIdApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringbootOpenIdApplication.class, args);
	}

}
