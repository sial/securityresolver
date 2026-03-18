package com.telekom.psa.domain;

/**
 * A single PSA security rule that can evaluate a code snippet.
 */
public interface Rule {

    Verdict evaluate(String snippet);

    String name();

    String identifier();

    String description();
}

