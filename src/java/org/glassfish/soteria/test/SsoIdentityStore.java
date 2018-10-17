/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.glassfish.soteria.test;

import static java.util.Collections.singleton;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import javax.security.enterprise.identitystore.IdentityStore;
import static javax.security.enterprise.identitystore.IdentityStore.ValidationType.VALIDATE;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Peter.pan
 */
@RequestScoped
public class SsoIdentityStore implements IdentityStore {
    private static final Logger logger = LoggerFactory.getLogger(SsoIdentityStore.class);
    public static final String SSO_SERVER = "http://sso.taiwancement.com/cas-server";
    public static final String SSO_VALIDATE_URI = "/v1/tickets";

    @PostConstruct
    public void init() {
        logger.debug("SsoIdentityStore init ...");
    }
    
    /**
     * 自定 IdentityStore 執行順序 - 預設 priority 為100，越小越先執行
     * @return 
     */
    @Override
    public int priority(){ 
         return 90;
    }
    
    @Override
    public CredentialValidationResult validate(Credential credential) {
        CredentialValidationResult result = NOT_VALIDATED_RESULT;
        String caller = null;
        if( credential instanceof UsernamePasswordCredential ){
            UsernamePasswordCredential usernamePassword = (UsernamePasswordCredential) credential;
            caller = usernamePassword.getCaller();
            // Validate By CAS Server 
            String tgt = validateByCAS(caller, usernamePassword.getPasswordAsString());
            if( tgt != null && !tgt.isEmpty() ){
                result = new CredentialValidationResult(usernamePassword.getCaller());
            } else {
                result = INVALID_RESULT;
            }
        }
        logger.info("validate caller = "+caller+", result ="+result.getStatus());
        return result;
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return singleton(VALIDATE);
    }

    /**
     * Validate By CAS Server 
     * @param caller
     * @param password
     * @return 
     */
    private String validateByCAS(String caller, String password){
        try{
            Client client = ClientBuilder.newBuilder().build();
            WebTarget target = client.target(SSO_SERVER);
            WebTarget resource = target.path(SSO_VALIDATE_URI)
                                        .queryParam("username", caller)
                                        .queryParam("password", password);
            Form form = new Form();
            form.param("username", caller).param("password", password);
            Response response = resource.request(MediaType.APPLICATION_FORM_URLENCODED)
                                                .accept(MediaType.TEXT_PLAIN)
                                                .post(Entity.form(form));
            String responseString = null;
            if( response.getStatus()==201 ){
                responseString = response.readEntity(String.class);
                Matcher matcher = Pattern.compile(".*action=\".*/(.*?)\".*").matcher(responseString);
                if( matcher.matches() ) {
                    return matcher.group(1);
                }
            }
            logger.error("validateByCAS caller = "+caller
                                    +", status="+response.getStatus()
                                    +", responseString = \n"+responseString);
        }catch(Exception e){
            logger.error("validateByCAS caller = "+caller+"\n", e);
        }
        return null;
    }
}
