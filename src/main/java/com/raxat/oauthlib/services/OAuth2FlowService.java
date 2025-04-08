package com.raxat.oauthlib.services;


import com.raxat.oauthlib.models.OAuth2Client;
import com.raxat.oauthlib.repositories.ClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

@Service
public class OAuth2FlowService {

    private final ClientRepository clientRepository;

    public OAuth2FlowService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    public RegisteredClient validateClient(String clientId, String clientSecret) {
        // Реализация проверки клиента
        return clientRepository.findByClientId(clientId)
                .map(this::toRegisteredClient)
                .orElseThrow(() -> new RuntimeException("Client not found"));
    }

    private RegisteredClient toRegisteredClient(OAuth2Client client) {
        // Конвертация из OAuth2Client в RegisteredClient
        return RegisteredClient.withId(client.getId().toString())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .build();
    }
}