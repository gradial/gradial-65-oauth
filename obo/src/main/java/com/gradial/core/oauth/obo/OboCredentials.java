package com.gradial.core.oauth.obo;

import javax.jcr.Credentials;

final class OboCredentials implements Credentials {
    private final String token;

    OboCredentials(String token) {
        this.token = token;
    }

    String token() {
        return token;
    }
}
