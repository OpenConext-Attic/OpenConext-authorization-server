package authzserver;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.io.Resource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigObject;

public class ClientsAndResourcesInitializer implements ApplicationListener<ContextRefreshedEvent> {

  private final Logger LOG = LoggerFactory.getLogger(ClientsAndResourcesInitializer.class);

  private final ClientRegistrationService clientRegistrationService;
  private final Resource resource;
  private final PlatformTransactionManager transactionManager;

  public ClientsAndResourcesInitializer(ClientRegistrationService clientRegistrationService, Resource resource, PlatformTransactionManager transactionManager) {
    this.clientRegistrationService = clientRegistrationService;
    this.resource = resource;
    this.transactionManager = transactionManager;
  }

  @Override
  public void onApplicationEvent(ContextRefreshedEvent event) {
    LOG.debug("Initializing default oAuth clients and resource-servers from {}", resource);
    try {
      Config config = ConfigFactory.parseReader(new InputStreamReader(resource.getInputStream()));

      final List<? extends ConfigObject> clients = config.getObjectList("clients");
      final List<? extends ConfigObject> resourceServers = config.getObjectList("resourceServers");

      new TransactionTemplate(transactionManager).execute((TransactionStatus transactionStatus) -> {

          List<ClientDetails> preExisting = clientRegistrationService.listClientDetails();
          clients.forEach(clientConfigObj -> {
            final Map<String, Object> clientConfig = clientConfigObj.unwrapped();
            final String clientId = (String) clientConfig.get("clientId");

            final Optional<ClientDetails> preExistingClientDetails =
              preExisting.stream()
                .filter(preExistingClient -> preExistingClient.getClientId().equals(clientId))
                .findFirst();

            BaseClientDetails clientDetails = preExistingClientDetails.isPresent() ? (BaseClientDetails) preExistingClientDetails.get() : new BaseClientDetails(clientId, null, null, null, null);

            final String secret = (String) clientConfig.get("secret");
            clientDetails.setClientSecret(secret);

            List<String> resourceIds = (List<String>) clientConfig.get("resourceIds");
            clientDetails.setResourceIds(resourceIds);

            final List<String> scopes = (List<String>) clientConfig.get("scopes");
            clientDetails.setScope(scopes);

            final List<String> grantTypes = (List<String>) clientConfig.get("grantTypes");
            clientDetails.setAuthorizedGrantTypes(grantTypes);

            final String redirectUri = (String) clientConfig.get("redirectUri");
            clientDetails.setRegisteredRedirectUri(ImmutableSet.of(redirectUri));

            if (preExistingClientDetails.isPresent()) {
              clientRegistrationService.updateClientDetails(clientDetails);
              clientRegistrationService.updateClientSecret(clientDetails.getClientId(), secret);
            } else {
              clientRegistrationService.addClientDetails(clientDetails);
            }
          });
          resourceServers.forEach(resourceServerConfigObj -> {

            final Map<String, Object> resourceServerConfig = resourceServerConfigObj.unwrapped();
            final String clientId = (String) resourceServerConfig.get("clientId");

            final Optional<ClientDetails> preExistingClientDetails =
              preExisting.stream()
                .filter(preExistingClient -> preExistingClient.getClientId().equals(clientId))
                .findFirst();

            BaseClientDetails clientDetails = preExistingClientDetails.isPresent() ? (BaseClientDetails) preExistingClientDetails.get() : new BaseClientDetails(clientId, null, null, null, null);
            // always add the token checker role
            clientDetails.setAuthorities(ImmutableList.of(new SimpleGrantedAuthority(AuthzServerApplication.ROLE_TOKEN_CHECKER)));
            final String secret = (String) resourceServerConfig.get("secret");
            clientDetails.setClientSecret(secret);
            clientDetails.setAuthorizedGrantTypes(Collections.emptyList());
            if (preExistingClientDetails.isPresent()) {
              clientRegistrationService.updateClientDetails(clientDetails);
              clientRegistrationService.updateClientSecret(clientDetails.getClientId(), secret);
            } else {
              clientRegistrationService.addClientDetails(clientDetails);
            }
          });
          return null;
        }
      );


    } catch (IOException e) {
      throw new RuntimeException("Unable to read configuration", e);
    }

  }
}
