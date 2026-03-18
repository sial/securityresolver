package com.telekom.psa.rule;

import com.telekom.psa.domain.Rule;
import java.util.List;

/**
 * Provides a list of PSA security rules.
 */
public interface Catalog {

    List<Rule> rules();
}

