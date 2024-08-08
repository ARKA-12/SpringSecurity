package com.luv2code.springboot.cruddemo.security;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
public class DemoSecurityConfig {

//adding support for JDBC ..no more hard code.....

@Bean

public UserDetailsManager userDetailsManager (DataSource  dataSource){  // inject the data source auto-configured by spring boot

        //return new JdbcUserDetailsManager(dataSource);// tell spring to use JDBC authentication with our data source.

        //custome table and coloum in spring security JDBC authentication
        JdbcUserDetailsManager jdbcUserDetailsManager =new JdbcUserDetailsManager(dataSource);

        //define a query to retrive a user by username(how to find user)
        jdbcUserDetailsManager.setUsersByUsernameQuery(
                "select user_id,pw,active from members where user_id=?"// regular SQL nothing fancy("?"  parameter value will be the user name from login)
        );

        //define a qurey for retrive the authorities/roles by username(how to find roles)
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                "select user_id,role from roles where user_id =?"
        );

        return jdbcUserDetailsManager;
}


    //retricting access based on roles

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(configurer ->
                                        configurer
                                        .requestMatchers(HttpMethod.GET,"/api/employees").hasRole("EMPLOYEE")
                                        .requestMatchers(HttpMethod.GET,"/api/employees/**").hasRole("EMPLOYEE")
                                        .requestMatchers(HttpMethod.POST,"/api/employees").hasRole("MANAGER")
                                        .requestMatchers(HttpMethod.PUT,"/api/employees/**").hasRole("MANAGER")
                                        .requestMatchers(HttpMethod.DELETE,"/api/employees/**").hasRole("ADMIN")
        );

        //teling spring using HTTP basic authentication
        http.httpBasic(Customizer.withDefaults());

        //disable Cross Site Request Forgery (CSRF)
        //in general, not required for stateless REST APIs that use  POST,PUT,DELETE and PATCH

        http.csrf(csrf ->csrf.disable());


        return http.build();


    }





    /* 
    @Bean//@Bean annotation is used before a method to instruct Spring to manage the object returned by that method as a bean

    //By marking the inMemoryUserDetailsManager method with @Bean, you tell Spring to manage the UserDetailsManager instance returned by that method. This means Spring takes care of creating the object, including any necessary configurations, and makes it available for injection into other security components.
    public InMemoryUserDetailsManager userDetailsManager() {

        UserDetails jhon = User.builder()
                .username("jhon")
                .password("{noop}test123")
                .roles("EMPLOYEE")
                .build();
        UserDetails mary = User.builder()
                .username("mary")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER")
                .build();

        UserDetails susan = User.builder()
                .username("susan")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER","ADMIN")
                .build();

        return new InMemoryUserDetailsManager(jhon,mary,susan);

    }

    */


}
