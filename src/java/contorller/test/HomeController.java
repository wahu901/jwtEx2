/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package contorller.test;

import java.io.Serializable;
import javax.annotation.PostConstruct;
import javax.annotation.security.RolesAllowed;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.security.enterprise.SecurityContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author peter.pan
 */
@ManagedBean(name = "home")
@ViewScoped
public class HomeController implements Serializable {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @ManagedProperty(value="#{sessionController}")
    protected TcSessionController sessionController;
    public TcSessionController getSessionController() {
        return sessionController;
    }

    public void setSessionController(TcSessionController sessionController) {
        this.sessionController = sessionController;
    }
    
    private String user;
    private boolean hasUserRole;
    
    @PostConstruct
    private void init() {
        logger.debug("HomeController init ...");
        
        user = sessionController.getLoginAccount();
        hasUserRole = sessionController.isUserInRole("ROLE_USER");
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public boolean isHasUserRole() {
        return hasUserRole;
    }

    public void setHasUserRole(boolean hasUserRole) {
        this.hasUserRole = hasUserRole;
    }    
}
