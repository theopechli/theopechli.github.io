---
title: 'CORS issues with RP-Initiated Logout'
description: ''
pubDate: 'Jan 25 2025'
---

## Table of Contents

## Introduction

I recently had some CORS issues with RP-Initiated Logout which, in the end, were easy to fix. Here's the setup:

- Frontend application
- Gateway
- Keycloak
- Apache HTTP Server

The client only has access to the [Apache HTTP Server](https://httpd.apache.org). In order for the client to access the frontend application, they access the aforementioned server. The server then routes them to the gateway, which itself routes them to the appropriate service, in this case the frontend application.

Everything worked beautifully! Or so I thought...

When the client made a post to `/logout`, an error would occur.

>Reason: CORS header 'Access-Control-Allow-Origin' missing

I was one of the people that had setup the server which, to my understanding, was setup correctly.

## Recon

As always, the moment a problem comes your way, you frantically search online hoping that another maidenless soul had come face to face with it, and in the end were victorious.

The only helpful thing I had found was this [OAuth2 Backend for Frontend With Spring Cloud Gateway](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2#bd-4-logout) blog post by [Baeldung](https://www.baeldung.com). Thankfully, even if the setup wasn't 1-1, their solution worked great.

## Code

If you didn't read the above blog post, the solution was basically to send a `202` HTTP status code, and handle the response in the frontend application.

To accomplish that, I simply modified the redirect strategy of the logout success handler. Note that after a successful logout, the client will be redirected to the frontend application.

The following code is almost the same as [this one from the Spring documentation](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/logout.html#configure-client-initiated-oidc-logout).

```java
@Configuration
@EnableWebSecurity
public class OAuth2LoginSecurityConfig {

	@Value("${frontend.url}")
	private String frontendUrl;

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.anyRequest().authenticated()
			)
			.oauth2Login(withDefaults())
			.logout(logout -> logout
				.logoutSuccessHandler(oidcLogoutSuccessHandler()
				.logoutUrl("/logout"))
			);
		return http.build();
	}

	private LogoutSuccessHandler oidcLogoutSuccessHandler() {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
				new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);

		// Sets the location that the End-User's User Agent will be redirected to
		// after the logout has been performed at the Provider
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri(frontendUrl);

		DefaultRedirectStrategy defaultRedirectStrategy = new DefaultRedirectStrategy();
		defaultRedirectStrategy.setStatusCode(HttpStatus.ACCEPTED);
		oidcLogoutSuccessHandler.setRedirectStrategy(defaultRedirectStrategy);

		return oidcLogoutSuccessHandler;
	}
}
```

In the frontend application, when the client makes a `POST` request to the logout endpoint, I check the response status. If it is `202`, the client will navigate to Keycloak in order to log out, and then will be redirected to the frontend application.

```js
async function logout() {
  const url = "http://example.com/logout";
  try {
    const response = await fetch(url, {
      method: "POST",
      // ...
    });

    if (response.status === 202) {
      const location = response.headers['location'];
      if (location) {
        window.location.href = location;
      } else {
        throw new Error('Failed to find Location header')
      }
    }
  } catch (error) {
    console.error(error.message);
  }
}
```

## Conclusion

After fiddling with the server's configuration again and again, I decided to go the other route and do something that may seem `hacky` by some people -- myself. I guess, some skill issues should stay as they are; skill issues. Anyway, this was fairly easy to solve thanks to Spring and, of course, to Baeldung, my beloved.
