package com.raxat.oauthlib.repositories;

import com.raxat.oauthlib.models.OAuth2Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ClientRepository extends JpaRepository<OAuth2Client, Long> {

    Optional<OAuth2Client> findByClientId(String clientId);

    @Query("SELECT c FROM OAuth2Client c WHERE c.clientId = :clientId AND c.clientSecret = :clientSecret")
    Optional<OAuth2Client> findByClientIdAndClientSecret(String clientId, String clientSecret);

    boolean existsByClientId(String clientId);
}