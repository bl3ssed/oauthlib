package com.raxat.oauthlib.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AuditService {

    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);

    // Получаем значения из application.yml
    @Value("${audit.log-level}")
    private String logLevel;

    @Value("${audit.max-logs}")
    private int maxLogs;

    public void logLoginSuccess(String username) {
        if ("DEBUG".equalsIgnoreCase(logLevel)) {
            logger.debug("User '{}' successfully logged in.", username);
        } else {
            logger.info("User '{}' successfully logged in.", username);
        }
    }

    // Другие методы для логирования
    public void logAction(String action) {
        logger.info("Action performed: {}", action);
    }

    // Можно использовать maxLogs для ограничения количества логов
    public int getMaxLogs() {
        return maxLogs;
    }
}
