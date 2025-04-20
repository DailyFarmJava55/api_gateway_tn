package telran.gateway;

import java.util.List;
import java.util.UUID;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFilter implements GatewayFilterFactory<AuthenticationFilter.Config> {

    private final WebClient.Builder webClientBuilder;

    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/auth/customer/login",
            "/auth/farmer/login",
            "/auth/customer/register",
            "/auth/farmer/register",
            "/auth/customer/refresh",
            "/auth/farmer/refresh"
    );

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getPath().value();

            // Allow public endpoints
            if (PUBLIC_ENDPOINTS.contains(path) && request.getMethod() == HttpMethod.POST) {
                return chain.filter(exchange);
            }

            // Validate token
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return unauthorized(exchange);
            }

            String token = authHeader.substring(7);

            return webClientBuilder.build()
                    .post()
                    .uri("http://auth-security-service:8080/internal/validate")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToMono(ValidationResponse.class)
                    .map(response -> {
                        // Add x-user-id and x-role to header
                        ServerHttpRequest modifiedRequest = request.mutate()
                                .header("x-user-id", response.userId().toString())
                                .header("x-role", response.role())
                                .build();
                        return exchange.mutate().request(modifiedRequest).build();
                    })
                    .flatMap(chain::filter);
        };
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Data
    public static class Config {
    }

    public record ValidationResponse(UUID userId, String role) {
    }
}
