package com.telekom.psa.web;

/**
 * Contract for the validation HTTP endpoint.
 */
public interface Endpoint {

    SnippetResponse validate(SnippetRequest request);
}

