package com.telekom.psa.engine;

import com.telekom.psa.domain.Report;

/**
 * Validates a code snippet against all registered PSA rules.
 */
public interface Engine {

    Report validate(String snippet);
}

