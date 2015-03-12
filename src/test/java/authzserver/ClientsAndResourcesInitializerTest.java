package authzserver;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.google.common.collect.ImmutableList;

@RunWith(MockitoJUnitRunner.class)
public class ClientsAndResourcesInitializerTest {

  private ClientsAndResourcesInitializer subject;

  @Mock
  private PlatformTransactionManager platformTransactionManager;

  @Mock
  private ClientRegistrationService clientRegistrationService;

  private final ContextRefreshedEvent mockEvent = new ContextRefreshedEvent(mock(ApplicationContext.class));

  @Before
  public void before() {
    TransactionTemplate transactionTemplate = new TransactionTemplate(platformTransactionManager);
    subject = new ClientsAndResourcesInitializer(clientRegistrationService, new ClassPathResource("/clientsAndResources.conf"), transactionTemplate);
  }

  @Test
  public void test_when_no_entries_exist_all_must_be_added() {
    final List<ClientDetails> preExistingClientsAndResources = ImmutableList.of();
    when(clientRegistrationService.listClientDetails()).thenReturn(preExistingClientsAndResources);

    subject.onApplicationEvent(mockEvent);

    verify(clientRegistrationService, times(3)).addClientDetails(any(ClientDetails.class));
  }

  @Test
  public void test_secrets_updated_separately() {

    final String clientId = "vootservice";
    final List<ClientDetails> preExistingClientsAndResources = ImmutableList.of(new BaseClientDetails(clientId, null, null, null, null));
    when(clientRegistrationService.listClientDetails()).thenReturn(preExistingClientsAndResources);

    subject.onApplicationEvent(mockEvent);

    verify(clientRegistrationService, times(2)).addClientDetails(any(ClientDetails.class));
    verify(clientRegistrationService, times(1)).updateClientSecret(clientId, "secret");
    verify(clientRegistrationService, times(1)).updateClientDetails(any(ClientDetails.class));
  }

}
