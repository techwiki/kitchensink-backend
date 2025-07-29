package org.jboss.quickstarts.kitchensink.dto;

import jakarta.validation.constraints.*;

public record AuthRequest(
    @NotNull
    @NotEmpty
    @Email
    String email,

    @NotNull
    @NotEmpty
    String password
) {} 