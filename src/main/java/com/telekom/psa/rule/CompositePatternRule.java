package com.telekom.psa.rule;

import com.telekom.psa.domain.Rule;
import com.telekom.psa.domain.RuleVerdict;
import com.telekom.psa.domain.Verdict;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A rule that checks for multiple forbidden patterns.
 * Fails if any of the patterns match.
 */
public final class CompositePatternRule implements Rule {

    private final String identifier;
    private final String name;
    private final String description;
    private final List<Pattern> patterns;

    public CompositePatternRule(
        final String identifier,
        final String name,
        final String description,
        final List<Pattern> patterns
    ) {
        this.identifier = identifier;
        this.name = name;
        this.description = description;
        this.patterns = patterns;
    }

    @Override
    public Verdict evaluate(final String snippet) {
        boolean violation = this.patterns.stream()
            .anyMatch(p -> p.matcher(snippet).find());
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

