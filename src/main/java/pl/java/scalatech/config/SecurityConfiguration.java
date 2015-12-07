package pl.java.scalatech.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@ComponentScan(basePackages="pl.java.scalatech.security")
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${logout.url}")
    private String logoutUrl;



    @Override
    public void configure(WebSecurity web) throws Exception {
        // @formatter:off
        web.ignoring().
        antMatchers("/assets/**")
        .antMatchers("/resources/**")
        .antMatchers("/favicon.ico")
        .antMatchers("/webjars/**");
        // @formatter:on
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //http.requiresChannel().anyRequest().requiresSecure();

        // @formatter:off
        http.csrf().disable().headers().disable()
          .authorizeRequests().antMatchers("/login","/logout","secContext","principal","/health","/console").permitAll()
          .antMatchers("/simple/**").hasAnyRole("USER")
          .antMatchers("/actuator/**").hasRole("ADMIN")
          .antMatchers("/metrics/**").hasRole("ADMIN")
          .antMatchers("/info/**").hasRole("ADMIN")
          .antMatchers("/health/**").hasRole("ADMIN")
          .antMatchers("/trace/**").hasRole("ADMIN")
          .antMatchers("/dump/**").hasRole("ADMIN")
          .antMatchers("/shutdown/**").hasRole("ADMIN")
          .antMatchers("/beans/**").hasRole("ADMIN")
          .antMatchers("/env/**").hasRole("ADMIN")
          .antMatchers("/autoconfig/**").hasRole("ADMIN")
          .anyRequest().authenticated().and()
          .formLogin().loginPage("/login").defaultSuccessUrl("/welcome").failureUrl("/login?errorFormLogin").permitAll()
          .and()
          .logout().permitAll();


           http.logout().logoutSuccessUrl(logoutUrl)
          .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
          .logoutSuccessUrl(logoutUrl);



          // @formatter:on
    }
    @Autowired
    public void configureGlobal(UserDetailsService userDetailsService,AuthenticationManagerBuilder auth) throws Exception {

        auth.userDetailsService(userDetailsService);
    }

}
