package server.signer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Collections;

@SpringBootApplication
public class CsrSignerApplication {

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(CsrSignerApplication.class);
		app.setDefaultProperties(Collections.singletonMap("server.port", "12000"));
		app.run(args);
	}

}
