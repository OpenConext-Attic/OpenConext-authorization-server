package authzserver.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@EqualsAndHashCode
public class LifeCycleResult {

  private String status = "OK";
  private String name = "OpenConext-authorization-server";
  private String message;
  private List<Attribute> data = new ArrayList<>();

  public void setData(List<Attribute> data) {
    this.data = data;
  }
}
