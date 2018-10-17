/*
 * Copyright (c) 2017 Payara Foundation and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://github.com/payara/Payara/blob/master/LICENSE.txt
 * See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * The Payara Foundation designates this particular file as subject to the "Classpath"
 * exception as provided by the Payara Foundation in the GPL Version 2 section of the License
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
package org.glassfish.soteria.test.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import org.slf4j.LoggerFactory;

public class TokenProvider {
    public final static org.slf4j.Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER = "Bearer ";
    public static final String AUTH_ROLES = "roles";

    // for HS256
    private String secretKey;
    // for RSA
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    private long tokenValidity;

    @PostConstruct
    public void init() {
        this.tokenValidity = TimeUnit.HOURS.toMillis(1);   //1 hours

        this.secretKey = "my-secret-jwt-key-34fsag550kmjdflnh";// for HS256
        // for RSA
        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);

            KeyPair kp = kpg.genKeyPair();
            publicKey = (RSAPublicKey)kp.getPublic();
            privateKey = (RSAPrivateKey)kp.getPrivate();
        }catch(Exception e){
            logger.error("init Exception :\n", e);
        }
    }

    public String createToken(String username, Set<String> authorities) {
        logger.debug("createToken: username:{}", username);
        try{
            long now = (new Date()).getTime();

            StringBuilder sb = new StringBuilder();
            if( authorities!=null ){
                for(String role : authorities){
                    sb.append(sb.toString().isEmpty()?"":",");
                    sb.append(role);
                }
            }
            logger.debug("createToken roles = "+sb.toString());
            
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(username)
                    .issueTime(new Date())
                    .issuer("http://www.taiwancement.com")
                    .claim(AUTH_ROLES, sb.toString())
                    .expirationTime(new Date(now + tokenValidity))
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
                    keyID("1").
                    jwkURL(new URI("http://www.taiwancement.com")).
                    build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);

            // JWSSigner signer = new MACSigner(sharedKey.getBytes());
            JWSSigner signer = new RSASSASigner(privateKey);
            
            signedJWT.sign(signer);

            String serializedJWT = signedJWT.serialize();
            return serializedJWT;
        }catch(Exception e){
            logger.error("init Exception :\n", e);
        }
        return null;
    }

    public JWTCredential getCredential(String token) throws ParseException, JOSEException {
        SignedJWT jwt = SignedJWT.parse(token);
        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        if( jwt.verify(verifier) ){
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            String caller = claimsSet.getSubject();
            
            Set<String> roles = Arrays.asList(claimsSet.getClaim(AUTH_ROLES).toString().split(","))
                                    .stream()
                                    .collect(Collectors.toSet());
            return new JWTCredential(caller, roles);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            //JWSVerifier verifier = new MACVerifier(sharedKey.getBytes());
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            return jwt.verify(verifier);
        } catch (ParseException | JOSEException e) {
            logger.debug("Invalid JWT signature: {}", e.getMessage());
            return false;
        }
    }
}
