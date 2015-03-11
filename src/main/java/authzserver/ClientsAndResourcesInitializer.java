package authzserver;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

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
      final Yaml yaml = new Yaml(new SafeConstructor());
      @SuppressWarnings("unchecked")
      Map<String, Object> content = (Map<String, Object>) yaml.load(resource.getInputStream());

      final List<Map<String, Object>> clients = (List<Map<String, Object>>) content.get("clients");
      final List<Map<String, Object>> resourceServers = (List<Map<String, Object>>) content.get("resourceServers");

      new TransactionTemplate(transactionManager).execute((TransactionStatus transactionStatus) -> {

          List<ClientDetails> preExisting = clientRegistrationService.listClientDetails();

          clients.forEach(clientYaml -> {
            final String clientId = (String) clientYaml.get("clientId");

            final Optional<ClientDetails> preExistingClientDetails =
              preExisting.stream()
                .filter(preExistingClient -> preExistingClient.getClientId().equals(clientId))
                .findFirst();

            BaseClientDetails clientDetails = preExistingClientDetails.isPresent() ? (BaseClientDetails) preExistingClientDetails.get() : new BaseClientDetails(clientId, null, null, null, null);

            final String secret = (String) clientYaml.get("secret");
            clientDetails.setClientSecret(secret);

            final List<String> resourceIds = (List<String>) clientYaml.get("resourceIds");
            clientDetails.setResourceIds(resourceIds);

            final List<String> scopes = (List<String>) clientYaml.get("scopes");
            clientDetails.setScope(scopes);

            final List<String> grantTypes = (List<String>) clientYaml.get("grantTypes");
            clientDetails.setAuthorizedGrantTypes(grantTypes);

            final String redirectUri = (String) clientYaml.get("redirectUri");
            clientDetails.setRegisteredRedirectUri(ImmutableSet.of(redirectUri));

            if (preExistingClientDetails.isPresent()) {
              clientRegistrationService.updateClientDetails(clientDetails);
              clientRegistrationService.updateClientSecret(clientDetails.getClientId(), secret);
            } else {
              clientRegistrationService.addClientDetails(clientDetails);
            }
          });

          resourceServers.forEach(resourceServerYaml -> {
            final String clientId = (String) resourceServerYaml.get("clientId");

            final Optional<ClientDetails> preExistingClientDetails =
              preExisting.stream()
                .filter(preExistingClient -> preExistingClient.getClientId().equals(clientId))
                .findFirst();

            BaseClientDetails clientDetails = preExistingClientDetails.isPresent() ? (BaseClientDetails) preExistingClientDetails.get() : new BaseClientDetails(clientId, null, null, null, null);
            // always add the token checker role
            clientDetails.setAuthorizedGrantTypes(ImmutableList.of(AuthzServerApplication.ROLE_TOKEN_CHECKER));
            final String secret = (String) resourceServerYaml.get("secret");
            clientDetails.setClientSecret(secret);

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
