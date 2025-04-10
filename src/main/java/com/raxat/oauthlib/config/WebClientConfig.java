package com.raxat.oauthlib.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.util.retry.Retry;
import reactor.netty.resources.ConnectionProvider;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLException;
import java.time.Duration;

@Configuration
public class WebClientConfig {

    @Value("${webclient.base-url}")
    private String baseUrl;

    @Value("${webclient.response-timeout}")
    private int responseTimeout;

    @Value("${webclient.max-connections}")
    private int maxConnections;

    @Value("${webclient.ssl}")
    private boolean sslEnabled;

    @Value("${webclient.retry.attempts}")
    private int retryAttempts;

    @Value("${webclient.retry.backoff}")
    private int retryBackoff;

    @Value("${webclient.max-in-memory-size}")
    private int maxInMemorySize;

    private static final Logger logger = LoggerFactory.getLogger(WebClientConfig.class);

    /**
     * Создает и настраивает WebClient для выполнения запросов с использованием кастомных настроек.
     *
     * Важные особенности:
     * 1. Используется SSLContext для безопасного HTTPS-соединения.
     * 2. Настроены таймауты на ответ от сервера.
     * 3. Ограничено количество одновременных соединений.
     * 4. Используется логирование запросов и ответов для отладки.
     * 5. Реализована логика повторных попыток для сетевых ошибок.
     *
     * @return настроенный WebClient
     * @throws SSLException если не удается создать SSL контекст
     */

    @Bean
    public WebClient webClient() throws SSLException {
        // 1. Настройка SSL-контекста для безопасного соединения
        SslContext sslContext = sslEnabled ? SslContextBuilder.forClient().build() : null;

        // 2. Создание кастомного HTTP-клиента с таймаутами и ограничениями
        ConnectionProvider provider = ConnectionProvider.builder("custom")
                .maxConnections(maxConnections) // Максимум одновременных соединений
                .build();

        HttpClient httpClient = HttpClient.create(provider)
                .responseTimeout(Duration.ofSeconds(responseTimeout)); // Таймаут на ответ от сервера

        if (sslEnabled) {
            httpClient = httpClient.secure(ssl -> ssl.sslContext(sslContext)); // Включаем HTTPS, если SSL включен
        }

        // 3. Сборка WebClient с настройками
        return WebClient.builder()
                .baseUrl(baseUrl) // Базовый URL для всех запросов
                .clientConnector(new ReactorClientHttpConnector(httpClient)) // Подключение кастомного HTTP-клиента
                .filter(logRequest()) // Фильтр для логирования запросов
                .filter(retryFilter()) // Фильтр для повторных попыток
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(maxInMemorySize)) // Макс. размер буфера
                .build();
    }

    /**
     * 4. Фильтр для логирования HTTP-запросов и ответов.
     * Логирует метод запроса, URL и статус ответа.
     *
     * @return ExchangeFilterFunction для логирования
     */
    private ExchangeFilterFunction logRequest() {
        return (clientRequest, next) -> {
            // Логирование запроса
            logger.info("Request: {} {}", clientRequest.method(), clientRequest.url());
            return next.exchange(clientRequest)
                    .doOnNext(response -> {
                        // Логирование ответа
                        logger.info("Response Status: {}", response.statusCode());
                    });
        };
    }


    /**
     * 5. Фильтр для повторных попыток запросов при сетевых ошибках.
     * При сетевых ошибках (например, WebClientRequestException) будет сделано до 3 повторных попыток.
     *
     * @return ExchangeFilterFunction для повторных попыток
     */
    private ExchangeFilterFunction retryFilter() {
        return (request, next) -> next.exchange(request)
                .retryWhen(Retry.backoff(retryAttempts, Duration.ofSeconds(retryBackoff)) // Повторные попытки с интервалом backoff
                        .filter(ex -> ex instanceof WebClientRequestException) // Повторять только при сетевых ошибках
                );
    }
}