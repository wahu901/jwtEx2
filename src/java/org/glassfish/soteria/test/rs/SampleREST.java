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
package org.glassfish.soteria.test.rs;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.security.enterprise.SecurityContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("sample")
public class SampleREST {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Inject
    private SecurityContext securityContext;
    
    @GET
    @Path("stateful")
    @RolesAllowed({"ROLE_USER", "ROLE_ADMIN"})
    public Response testStateful() {
        logger.debug("read ...");
        if( securityContext.getCallerPrincipal()!=null ){
            logger.debug("securityContext.getCallerPrincipal().getName() = "+securityContext.getCallerPrincipal().getName());
            logger.debug("securityContext.isCallerInRole(\"ROLE_USER\") = "+securityContext.isCallerInRole("ROLE_USER"));
        }

        JsonObject result = Json.createObjectBuilder()
                .add("user", securityContext.getCallerPrincipal() != null
                        ? securityContext.getCallerPrincipal().getName() : "Anonymous")
                .add("message", "test stateful client")
                .build();
        return Response.ok(result).build();
    }

    /**
     * /resources/sample/read
     * @return 
     */
    @GET
    @Path("read")
    @PermitAll
    public Response read() {
        logger.debug("read ...");
        JsonObject result = Json.createObjectBuilder()
                .add("user", securityContext.getCallerPrincipal() != null
                        ? securityContext.getCallerPrincipal().getName() : "Anonymous")
                .add("message", "Read resource")
                .build();
        return Response.ok(result).build();
    }

    /**
     * /resources/sample/write
     * @param data
     * @return 
     */
    @POST
    @Path("write")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    //RolesAllowed({"ROLE_USER", "ROLE_ADMIN"}) // test set security-constraint in web.xml
    public Response write(TestData data) {
        logger.debug("write ...");
        JsonObject result = Json.createObjectBuilder()
                .add("user", securityContext.getCallerPrincipal().getName())
                .add("message", "Write resource")
                .build();
        return Response.ok(result).build();
    }

    /**
     * /resources/sample/delete
     * @return 
     */
    @POST
    @Path("delete")
    @RolesAllowed({"ROLE_ADMIN"})
    public Response delete() {
        logger.debug("delete ...");
        JsonObject result = Json.createObjectBuilder()
                .add("user", securityContext.getCallerPrincipal().getName())
                .add("message", "Delete resource")
                .build();
        return Response.ok(result).build();
    }
}
