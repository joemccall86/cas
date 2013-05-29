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
package org.jasig.cas.support.oauth;

import java.util.ArrayList;
import java.util.Collection;

import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * A spring security authentication provider that is meant to be run on the same webapp as CAS. The CAS authentication
 * manager is called directly rather than through an HTTP call, so no ticket granting ticket is created; only whether
 * or not the user is authenticated.
 *
 * @author Joe McCall
 *
 */
public class CasServerAuthenticationProvider implements AuthenticationProvider {

    @NotNull
    private AuthenticationManager casAuthenticationManager;

    public CasServerAuthenticationProvider(final AuthenticationManager casAuthenticationManager) {
        super();
        this.casAuthenticationManager = casAuthenticationManager;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if ((authentication.getCredentials() == null) || "".equals(authentication.getCredentials())) {
            throw new BadCredentialsException("TODO: no credentials");
        }

        UsernamePasswordCredentials casCredentials = new UsernamePasswordCredentials();
        casCredentials.setUsername((String) authentication.getPrincipal());
        casCredentials.setPassword((String) authentication.getCredentials());


        org.jasig.cas.authentication.Authentication result;

        try {
            result = casAuthenticationManager.authenticate(casCredentials);
        } catch (final org.jasig.cas.authentication.handler.AuthenticationException e) {
            throw new BadCredentialsException("CAS Exception Thrown: " + e.getLocalizedMessage());
        }

        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_CAS_USER"));

        return new UsernamePasswordAuthenticationToken(result.getPrincipal(), authentication.getCredentials(),
                authorities);
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
