package com.telekom.psa.engine;

import com.telekom.psa.domain.Report;
import com.telekom.psa.domain.Rule;
import com.telekom.psa.domain.ValidationReport;
import com.telekom.psa.domain.Verdict;
import java.util.List;

/**
 * Iterates all PSA rules and produces a validation report.
 */
public final class Validator implements Engine {

    private final List<Rule> rules;

    public Validator(final List<Rule> rules) {
        this.rules = rules;
    }

    @Override
    public Report validate(final String snippet) {
        List<Verdict> verdicts = this.rules.stream()
            .map(r -> r.evaluate(snippet))
            .toList();
        return new ValidationReport(verdicts);
    }
}

