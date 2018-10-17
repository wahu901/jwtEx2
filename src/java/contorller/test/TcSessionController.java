/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package contorller.test;

import java.io.Serializable;
import javax.annotation.PostConstruct;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.security.enterprise.SecurityContext;
import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author peter.pan
 */
@ManagedBean(name = "sessionController")
@SessionScoped
public class TcSessionController implements Serializable {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    
    @Inject
    private SecurityContext securityContext;
    
    private String loginAccount;

    @PostConstruct
    public void init() {
        logger.info("TcSessionController init ...");
        logger.debug("HomeController securityContext = "+securityContext);
        if( securityContext!=null ){
            if( securityContext.getCallerPrincipal()!=null ){
                loginAccount = securityContext.getCallerPrincipal().getName();
            }else{
                logger.debug("securityContext.getCallerPrincipal() is null !");
            }
        }
    }
    
    public boolean isUserInRole(String roleNameList) {
        String[] roles = roleNameList.split(",");
        FacesContext context = FacesContext.getCurrentInstance();
        //HttpServletRequest request = (HttpServletRequest) context.getExternalContext().getRequest();
        boolean roleFound = false;
        for (String roleName : roles) {
            if( securityContext.isCallerInRole(roleName) ) {
                roleFound = true;
                break;
            }
        }
        return roleFound;
    }

    public String getLoginAccount() {
        return loginAccount;
    }

    public void setLoginAccount(String loginAccount) {
        this.loginAccount = loginAccount;
    }


}
