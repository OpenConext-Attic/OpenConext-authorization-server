package authzserver.web;

import org.junit.Test;

import java.util.Properties;

import static org.junit.Assert.*;

public class GitPluginControllerTest {

  @Test
  public void testGit() throws Exception {
    Properties git = new GitPluginController().git();
    assertEquals(15, git.size());
  }
}
