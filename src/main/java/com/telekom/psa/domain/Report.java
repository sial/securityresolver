package com.telekom.psa.domain;

import java.util.List;

/**
 * Represents a collection of verdicts forming a complete validation report.
 */
public interface Report {

    List<Verdict> verdicts();

    long violations();

    long passes();
}

