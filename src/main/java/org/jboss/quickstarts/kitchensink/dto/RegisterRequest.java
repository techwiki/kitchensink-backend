package org.jboss.quickstarts.kitchensink.dto;

public record RegisterRequest(String email, String password, String name, String phoneNumber) {} 