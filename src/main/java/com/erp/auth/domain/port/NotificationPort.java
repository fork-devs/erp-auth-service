package com.erp.auth.domain.port;

import com.erp.auth.domain.model.NotificationMessage;

/**
 * Delivery of a notification to a recipient.
 *
 * <p>This is a domain port decoupled from any specific provider: it has no knowledge
 * of email, SMS, or instant messaging. The infrastructure adapter determines delivery mechanics.
 *
 * <p>It exists so that password reset tokens reach their intended recipient securely.
 * Returning the token in the API response is unacceptable: anyone requesting a reset
 * could read the response and take over arbitrary accounts.
 */
public interface NotificationPort {

    void deliver(NotificationMessage notification);
}
