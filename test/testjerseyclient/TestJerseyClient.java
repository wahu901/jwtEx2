/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package testjerseyclient;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.glassfish.soteria.test.rs.TestData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Peter.pan
 */
public class TestJerseyClient {
    private static final Logger logger = LoggerFactory.getLogger(TestJerseyClient.class);
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //String authStrWithJWT = testLoginGetJWT("admin", "abcd1234");// ROLE_USER、ROLE_ADMIN
        //String authStrWithJWT = testLoginGetJWT("payara", "abcd1234");// ROLE_USER
        //String authStrWithJWT = testLoginGetJWT("duke", "abcd1234");// NONE
        String authStrWithJWT = testLoginGetJWT("devadmin", "Abcd1234");// ROLE_USER
        
        testServletWithJWT(authStrWithJWT);
        
        testRestWithJWT(authStrWithJWT, "/sample/read", false);
        testRestWithJWT(authStrWithJWT, "/sample/write", true);
        testRestWithJWT(authStrWithJWT, "/sample/delete", true);
    }
    
    public static String testLoginGetJWT(String account, String password){
        Client client = ClientBuilder.newBuilder().build();
        WebTarget target = client.target("http://localhost:8080/jwtEx2");
        WebTarget resource = target.path("/servlet")
                .queryParam("name", account)
                .queryParam("password", password);

        Response res = resource.request(MediaType.TEXT_PLAIN).get();
        int status = res.getStatus();
        String authStr = res.getHeaderString(HttpHeaders.AUTHORIZATION);
        String msg = res.readEntity(String.class);
        
        logger.debug("status = "+status);
        logger.debug("authStr = "+authStr);
        logger.debug("msg = "+msg);
        
        client.close();
        return authStr;
    }
    
    public static void testServletWithJWT(String authStr){
        Client client = ClientBuilder.newBuilder().build();
        WebTarget target = client.target("http://localhost:8080/jwtEx2");
        WebTarget resource = target.path("/servlet");

        Response res = resource.request(MediaType.TEXT_PLAIN)
                                .header(HttpHeaders.AUTHORIZATION, authStr)
                                .get();
        int status = res.getStatus();
        String msg = res.readEntity(String.class);
        
        logger.debug("status = "+status);
        logger.debug("msg = "+msg);
        
        client.close();
    }

    public static void testRestWithJWT(String authStr, String path, boolean post){
        Client client = ClientBuilder.newBuilder().build();
        WebTarget target = client.target("http://localhost:8080/jwtEx2");
        WebTarget resource = target.path("/resources").path(path);

        Invocation.Builder builder = resource.request(MediaType.APPLICATION_JSON)
                                .header(HttpHeaders.AUTHORIZATION, authStr);
        
        Response res;
        if( post ){
            TestData entity = new TestData("p1", "p2");
            res = builder.post(Entity.entity(entity, MediaType.APPLICATION_JSON_TYPE));
        }else{
            res = builder.get();
        }
        
        int status = res.getStatus();
        String msg = res.readEntity(String.class);
        
        logger.debug("status = "+status);
        logger.debug("msg = "+msg);
        
        client.close();
    }
}
