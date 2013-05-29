/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.support.oauth.token;

import javax.validation.constraints.NotNull;

import org.jasig.cas.ticket.Ticket;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.registry.TicketRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

/**
 * Resets the value of the oauth token to the found TGT for that authentication.
 * @author Joe McCall
 *
 */
public class CasTGTTokenEnhancer implements TokenEnhancer {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasTGTTokenEnhancer.class);

    @NotNull
    private TokenExpirationConfig tokenExpirationConfig;

    @NotNull
    private TicketRegistry casTicketRegistry;

    public CasTGTTokenEnhancer(final TokenExpirationConfig tokenExpirationConfig, final TicketRegistry casTicketRegistry) {
        this.tokenExpirationConfig = tokenExpirationConfig;
        this.casTicketRegistry = casTicketRegistry;
    }

    @Override
    public OAuth2AccessToken enhance(final OAuth2AccessToken accessToken, final OAuth2Authentication authentication) {
        // Get the user from the authentication
        String casUserName = authentication.getName();

        DefaultOAuth2AccessToken returnAccessToken = null;

        LOGGER.debug("There are {} tickets in the ticket registry", casTicketRegistry.getTickets().size());

        // Then find the TGT for that user
        for (Ticket casTicket: casTicketRegistry.getTickets()) {
            LOGGER.debug("Checking ticket for value {}", casTicket.getId());
            if (casTicket instanceof TicketGrantingTicket) {
                TicketGrantingTicket casTGT = (TicketGrantingTicket) casTicket;
                if (casUserName.equals(casTGT.getAuthentication().getPrincipal().getId())) {
                    LOGGER.debug("Setting the returnAccessToken value to {}", casTGT.getId());
                    LOGGER.debug("Setting the exipation to {}", tokenExpirationConfig.getAccessTokenValiditySeconds());
                    returnAccessToken = new CasTGTOAuth2AccessToken(casTGT, tokenExpirationConfig.getAccessTokenValiditySeconds());
                    break;
                }
            }
        }

        return returnAccessToken != null? returnAccessToken : accessToken;
    }
}
