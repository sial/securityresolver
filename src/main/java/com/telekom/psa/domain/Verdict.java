package com.telekom.psa.domain;

/**
 * Represents the outcome of evaluating a single PSA rule against a code snippet.
 */
public interface Verdict {

    String rule();

    boolean passed();

    String reason();
}

