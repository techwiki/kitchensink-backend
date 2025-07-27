package org.jboss.quickstarts.kitchensink.model;

import jakarta.validation.constraints.*;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document(collection = "members")
public class Member {
    @Id
    private String id;

    @NotNull
    @Size(min = 1, max = 25)
    @Pattern(regexp = "[^0-9]*", message = "Must not contain numbers")
    private String name;

    @NotNull
    @NotEmpty
    @Email
    @Indexed(unique = true)
    private String email;

    @NotNull
    @Size(min = 10, max = 12)
    @Pattern(regexp = "\\d+", message = "Must contain only digits")
    private String phoneNumber;
} 