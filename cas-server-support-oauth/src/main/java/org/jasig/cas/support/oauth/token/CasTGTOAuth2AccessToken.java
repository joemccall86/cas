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

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.jasig.cas.ticket.TicketGrantingTicket;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

/**
 * Represents an access token that contains a CAS TGT ID as the value and the TGT expiration information in access
 * token form.
 *
 * @author Joe McCall
 */
public class CasTGTOAuth2AccessToken extends DefaultOAuth2AccessToken {

    private static final long serialVersionUID = 1L;

    public CasTGTOAuth2AccessToken(final TicketGrantingTicket casTGT, final Long timeToKillInSeconds) {
        super(casTGT.getId());

        long timeLeft =
                TimeUnit.SECONDS.toMillis(timeToKillInSeconds)
                - System.currentTimeMillis() + casTGT.getCreationTime();

        this.setExpiration(new Date(System.currentTimeMillis() + timeLeft));
        this.setExpiresIn((int) timeLeft);

        // No scope... for now
    }

}
