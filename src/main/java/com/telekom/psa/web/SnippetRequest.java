package com.telekom.psa.web;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Incoming request payload for code snippet validation.
 */
public final class SnippetRequest {

    private final String snippet;

    @JsonCreator
    public SnippetRequest(@JsonProperty("snippet") final String snippet) {
        this.snippet = snippet;
    }


    public String snippet() {
        return this.snippet;
    }
}

