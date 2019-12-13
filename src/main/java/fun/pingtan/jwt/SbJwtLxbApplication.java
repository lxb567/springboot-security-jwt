package fun.pingtan.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.transaction.annotation.Transactional;

@SpringBootApplication
public class SbJwtLxbApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(SbJwtLxbApplication.class, args);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(SbJwtLxbApplication.class);
    }
}
