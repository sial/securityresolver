package com.telekom.psa.rule;

import com.telekom.psa.domain.Rule;
import com.telekom.psa.domain.RuleVerdict;
import com.telekom.psa.domain.Verdict;
import java.util.regex.Pattern;

/**
 * A rule that detects violations via a regex pattern.
 * When the pattern matches, the snippet is in violation (failed).
 */
public final class PatternRule implements Rule {

    private final String identifier;
    private final String name;
    private final String description;
    private final Pattern pattern;

    public PatternRule(
        final String identifier,
        final String name,
        final String description,
        final Pattern pattern
    ) {
        this.identifier = identifier;
        this.name = name;
        this.description = description;
        this.pattern = pattern;
    }

    @Override
    public Verdict evaluate(final String snippet) {
        boolean violation = this.pattern.matcher(snippet).find();
        if (violation) {
            return new RuleVerdict(
                this.identifier,
                false,
                "Violation of " + this.identifier + ": " + this.name
            );
        }
        return new RuleVerdict(
            this.identifier,
            true,
            "No violation detected for " + this.identifier
        );
    }

    @Override
    public String name() {
        return this.name;
    }

    @Override
    public String identifier() {
        return this.identifier;
    }

    @Override
    public String description() {
        return this.description;
    }
}

