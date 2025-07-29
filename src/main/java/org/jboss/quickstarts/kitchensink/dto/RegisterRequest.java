package org.jboss.quickstarts.kitchensink.dto;

import jakarta.validation.constraints.*;

public record RegisterRequest(
    @NotNull
    @NotEmpty
    @Email
    String email,

    @NotNull
    @NotEmpty
    String password,

    @NotNull
    @Size(min = 1, max = 25)
    @Pattern(regexp = "[^0-9]*", message = "Must not contain numbers")
    String name,

    @NotNull
    @Size(min = 10, max = 12)
    @Pattern(regexp = "\\d+", message = "Must contain only digits")
    String phoneNumber
) {} 