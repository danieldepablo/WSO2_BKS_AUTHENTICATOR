/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.santander.serenity.security.credentials.bkstoken;

import com.santander.serenity.security.credentials.bkstoken.internal.BKSAuthenticatorServiceComponent;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.core.services.authentication.CarbonServerAuthenticator;
import org.wso2.carbon.core.services.util.CarbonAuthenticationUtil;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.user.api.TenantManager;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.ldap.ReadWriteLDAPUserStoreManager;
import org.wso2.carbon.utils.AuthenticationObserver;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

/**
 * BKSAuthenticator.
 */
public class BKSAuthenticator implements CarbonServerAuthenticator {
    private static int DEFAULT_PRIORITY_LEVEL = 50;
    private static final String AUTHENTICATOR_NAME = "BKSAuthenticator";
    private static final Log log = LogFactory.getLog(BKSAuthenticator.class);

    @Override
    public int getPriority() {
        AuthenticatorsConfiguration authenticatorsConfiguration =
                AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(AUTHENTICATOR_NAME);
        if (authenticatorConfig != null && authenticatorConfig.getPriority() > 0) {
            return authenticatorConfig.getPriority();
        }
        return DEFAULT_PRIORITY_LEVEL;
    }

    @Override
    public boolean isDisabled() {
        AuthenticatorsConfiguration authenticatorsConfiguration =
                AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(AUTHENTICATOR_NAME);
        return authenticatorConfig != null && authenticatorConfig.isDisabled();
    }

    @Override
    public boolean authenticateWithRememberMe(MessageContext msgCxt) {
        return false;
    }

    @Override
    public String getAuthenticatorName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public boolean isAuthenticated(MessageContext msgCxt) {
        boolean isAuthenticated = false;
        HttpServletRequest request =
                (HttpServletRequest) msgCxt.getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST);
        
        
        //Get the filesystem keystore default primary certificate
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(
                MultitenantConstants.SUPER_TENANT_ID);
        
        BKSToken token = BKSToken.parse(request.getParameter("token"));

        //Validar caducidad
        if (System.currentTimeMillis() > token.getExpirationDate()) {
            log.info("BKSToken is expired");
            return false;
        }
        
        //Valida la firma
        try {
            String publicKeyAlias = token.getEmitter() + "_" + token.getSignatureMethod();
            Signature verifier = Signature.getInstance(token.getSignatureMethod());
            verifier.initVerify((RSAPublicKey) keyStoreManager.getPrimaryKeyStore().getCertificate(publicKeyAlias+".cer").getPublicKey());
            verifier.update(token.getOriginalDataWithoutSignature().getBytes());

            if (!verifier.verify(Base64Utils.decode(token.getSignature()))){
                return false;
            }
        }catch (Exception e){
            log.error(e.getMessage());
            return false;
        }
            
        //Valida que exista el usuario en el repo de usuarios
        try{
            String userName = token.getUserId();
            String tenantDomain = MultitenantUtils.getTenantDomain(userName);
            userName = MultitenantUtils.getTenantAwareUsername(userName);
            TenantManager tenantManager = BKSAuthenticatorServiceComponent
                        .getRealmService().getTenantManager();
            int tenantId = tenantManager.getTenantId(tenantDomain);

            if (tenantId == -1) {
                log.error("tenantDomain is not valid. username : " + userName + ", tenantDomain : " + tenantDomain);
                return false;
            }

            handleAuthenticationStarted(tenantId);
        
            UserStoreManager userStore = ((ReadWriteLDAPUserStoreManager)BKSAuthenticatorServiceComponent
                    .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager()).getSecondaryUserStoreManager();
            if (userStore.isExistingUser(userName)) {
                isAuthenticated = true;
            }

            if (isAuthenticated) {
                CarbonAuthenticationUtil.onSuccessAdminLogin(request.getSession(), userName,
                        tenantId, tenantDomain,
                        "BKSTToken Authentication");
                handleAuthenticationCompleted(tenantId, true);
                return true;
            } else {
                log.error("Authentication Request is rejected. User : " + userName
                        + " does not exists in tenant : " + tenantDomain + " 's UserStore");
                CarbonAuthenticationUtil
                        .onFailedAdminLogin(request.getSession(), userName, tenantId,
                                "BKSToken Authentication",
                                "User does not exists in UserStore");
                handleAuthenticationCompleted(tenantId, false);
                return false;
            }
            
        } catch (Exception e) {
            log.error("Error authenticating the user " + e.getMessage(), e);
        }
        return isAuthenticated;
    }
    
    
    @Override
    public boolean isHandle(MessageContext msgCxt) {
        HttpServletRequest request =  (HttpServletRequest) msgCxt.getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST);
        return (null != request.getParameter("token") && !request.getParameter("token").isEmpty())? true: false;
    }

    private void handleAuthenticationStarted(int tenantId) {
        BundleContext bundleContext = BKSAuthenticatorServiceComponent.getBundleContext();
        if (bundleContext != null) {
            ServiceTracker tracker =
                    new ServiceTracker(bundleContext,
                            AuthenticationObserver.class.getName(), null);
            tracker.open();
            Object[] services = tracker.getServices();
            if (services != null) {
                for (Object service : services) {
                    ((AuthenticationObserver) service).startedAuthentication(tenantId);
                }
            }
            tracker.close();
        }
    }

    private void handleAuthenticationCompleted(int tenantId, boolean isSuccessful) {
        BundleContext bundleContext = BKSAuthenticatorServiceComponent.getBundleContext();
        if (bundleContext != null) {
            ServiceTracker tracker =
                    new ServiceTracker(bundleContext,
                            AuthenticationObserver.class.getName(), null);
            tracker.open();
            Object[] services = tracker.getServices();
            if (services != null) {
                for (Object service : services) {
                    ((AuthenticationObserver) service).completedAuthentication(
                            tenantId, isSuccessful);
                }
            }
            tracker.close();
        }
    }

}
