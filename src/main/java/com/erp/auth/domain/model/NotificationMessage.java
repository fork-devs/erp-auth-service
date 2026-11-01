package com.erp.auth.domain.model;

import java.time.Instant;

/**
 * Notification message to be delivered to a recipient.
 *
 * <p>This is a domain model, not provider-specific: it has no knowledge of
 * SMTP, email, or SMS. The infrastructure adapter determines how it is delivered.
 */
public record NotificationMessage(
        String recipient,
        String subject,
        String body,
        Instant createdAt
) {

    public static NotificationMessage of(String recipient, String subject, String body) {
        return new NotificationMessage(recipient, subject, body, Instant.now());
    }
}
