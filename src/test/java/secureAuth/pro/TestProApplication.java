package secureAuth.pro;

import org.springframework.boot.SpringApplication;

public class TestProApplication {

	public static void main(String[] args) {
		SpringApplication.from(ProApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
