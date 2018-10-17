/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.glassfish.soteria.test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import static javax.security.enterprise.identitystore.IdentityStore.ValidationType.PROVIDE_GROUPS;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Peter.pan
 */
public class AuthorizationIdentityStore implements IdentityStore {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Resource(lookup="jdbc/testDB")
    private DataSource dataSource;
    
    @Resource(mappedName = "jndi/jwtEx2.config")
    protected Properties jndiConfig;

    @PostConstruct
    public void init() {
    }

    @Override
    public Set<String> getCallerGroups(CredentialValidationResult validationResult) {
        String caller = validationResult.getCallerPrincipal().getName();

        Set<String> result = findCallerGroups(dataSource, getGroupsQuery(), caller);
        if (result == null) {
            result = Collections.emptySet();
        }
        logger.info("getCallerGroups caller = "+caller+", result = "+result.size());
        return result;
    }

    @Override
    public Set<IdentityStore.ValidationType> validationTypes() {
        return Collections.singleton(PROVIDE_GROUPS);
    }
    
    public String getGroupsQuery(){
        return jndiConfig.getProperty("groupsQuery");
    }
    
    private Set<String> findCallerGroups(DataSource dataSource, String query, String caller) {
        logger.info("findCallerGroups query = "+query+", caller = "+caller);
        try (Connection connection = dataSource.getConnection()) {
            List<String> groups = new ArrayList<String>();
            try (PreparedStatement statement = connection.prepareStatement(query)) {
                statement.setString(1, caller);
                ResultSet rs = statement.executeQuery();
                while(rs.next()){
                    logger.info("findCallerGroups rs = "+rs.getString(1));
                    groups.add(rs.getString(1));
                }
            }
            return new HashSet<>(groups);
        } catch (SQLException e) {
           logger.error("findCallerGroups exception:\n", e);
        }
        return Collections.emptySet();
    }
}
