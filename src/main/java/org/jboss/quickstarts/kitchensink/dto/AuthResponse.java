package org.jboss.quickstarts.kitchensink.dto;

public record AuthResponse(String token) {
    public static AuthResponseBuilder builder() {
        return new AuthResponseBuilder();
    }

    public static class AuthResponseBuilder {
        private String token;

        public AuthResponseBuilder token(String token) {
            this.token = token;
            return this;
        }

        public AuthResponse build() {
            return new AuthResponse(token);
        }
    }
} 