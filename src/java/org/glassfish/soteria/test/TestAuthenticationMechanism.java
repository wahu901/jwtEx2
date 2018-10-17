/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2015-2017 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://oss.oracle.com/licenses/CDDL+GPL-1.1
 * or LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
package org.glassfish.soteria.test;

import java.util.Set;
import org.glassfish.soteria.test.jwt.TokenProvider;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.CallerPrincipal;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import javax.servlet.http.HttpSession;
import org.glassfish.soteria.test.jwt.JWTCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class TestAuthenticationMechanism implements HttpAuthenticationMechanism {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final String CALLER_ATTR = "_SC_CALLER_";
    private final String GROUPS_ATTR = "_SC_GROUPS_";
    
    @Inject
    private IdentityStoreHandler identityStoreHandler;

    @Inject
    private TokenProvider tokenProvider;

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
        if (request.getParameter("name") != null && request.getParameter("password") != null) {
            // Get the (caller) name and password from the request
            // NOTE: This is for the smallest possible example only. In practice
            // putting the password in a request query parameter is highly
            // insecure
            String name = request.getParameter("name");
            Password password = new Password(request.getParameter("password"));
            logger.debug("validateRequest name ="+request.getParameter("name"));
            
            // Delegate the {credentials in -> identity data out} function to
            // the Identity Store
            CredentialValidationResult result = identityStoreHandler.validate(
                new UsernamePasswordCredential(name, password));
            logger.debug("validateRequest result.getStatus() ="+result.getStatus());
            
            if( result.getStatus() == VALID ){
                // Communicate the details of the authenticated user to the
                // container. In many cases the underlying handler will just store the details 
                // and the container will actually handle the login after we return from 
                // this method.
                return createToken(result, httpMessageContext);
            } else {
                return httpMessageContext.responseUnauthorized();
            }
        }
        
        String token = extractToken(httpMessageContext);
        if (token != null) {
            // validation of the jwt credential
            return validateToken(token, httpMessageContext);
        } else if (httpMessageContext.isProtected()) {
            // === for stateful client ====
            HttpSession session = httpMessageContext.getRequest().getSession();
            if( session!=null ){
                CallerPrincipal caller  = (CallerPrincipal)session.getAttribute(CALLER_ATTR);// CallerPrincipal
                Set<String> groups  = (Set<String>)session.getAttribute(GROUPS_ATTR);// Set<String>
                if( caller!=null ){
                    logger.debug("validateRequest caller = "+caller.getName());
                    return  httpMessageContext.notifyContainerAboutLogin(caller, groups);
                }
            }
            // ============================
            // A protected resource is a resource for which a constraint has been defined.
            // if there are no credentials and the resource is protected, we response with unauthorized status
            return httpMessageContext.responseUnauthorized();
        }
        // there are no credentials AND the resource is not protected, 
        // SO Instructs the container to "do nothing"

        return httpMessageContext.doNothing();
    }

    /**
     * Create the JWT using CredentialValidationResult received from
     * IdentityStoreHandler
     *
     * @param result the result from validation of UsernamePasswordCredential
     * @param context
     * @return the AuthenticationStatus to notify the container
     */
    private AuthenticationStatus createToken(CredentialValidationResult result, HttpMessageContext context) {
        String jwt = tokenProvider.createToken(result.getCallerPrincipal().getName(), result.getCallerGroups());
        context.getResponse().setHeader(TokenProvider.AUTHORIZATION_HEADER, TokenProvider.BEARER + jwt);

        // === for stateful client ====
        HttpSession session = context.getRequest().getSession(true);
        session.setAttribute(CALLER_ATTR, result.getCallerPrincipal());// CallerPrincipal
        session.setAttribute(GROUPS_ATTR, result.getCallerGroups());// Set<String>
        // ============================

        return context.notifyContainerAboutLogin(result.getCallerPrincipal(), result.getCallerGroups());
    }
    
    /**
     * To extract the JWT from Authorization HTTP header
     *
     * @param context
     * @return The JWT access tokens
     */
    private String extractToken(HttpMessageContext context) {
        String authorizationHeader = context.getRequest().getHeader(TokenProvider.AUTHORIZATION_HEADER);
        if (authorizationHeader != null && authorizationHeader.startsWith(TokenProvider.BEARER)) {
            String token = authorizationHeader.substring(TokenProvider.BEARER.length(), authorizationHeader.length());
            return token;
        }
        return null;
    }
    
    /**
     * To validate the JWT token e.g Signature check, JWT claims
     * check(expiration) etc
     *
     * @param token The JWT access tokens
     * @param context
     * @return the AuthenticationStatus to notify the container
     */
    private AuthenticationStatus validateToken(String token, HttpMessageContext context) {
        try {
            if (tokenProvider.validateToken(token)) {
                logger.debug("validateToken valid.");
                JWTCredential credential = tokenProvider.getCredential(token);                
                return context.notifyContainerAboutLogin(credential.getPrincipal(), credential.getAuthorities());
            }
            // if token invalid, response with unauthorized status
            logger.debug("validateToken invalid.");
            return context.responseUnauthorized();
        } catch (Exception e) {
            logger.info("validateToken Exception:\n", e);
            return context.responseUnauthorized();
        }
    }
}
