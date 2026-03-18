package com.telekom.psa.rule;

import com.telekom.psa.domain.Rule;
import com.telekom.psa.domain.RuleVerdict;
import com.telekom.psa.domain.Verdict;
import java.util.regex.Pattern;

/**
 * A rule that requires a specific pattern to be present in the snippet.
 * When the pattern is absent, the snippet is in violation (failed).
 */
public final class RequiredPatternRule implements Rule {

    private final String identifier;
    private final String name;
    private final String description;
    private final Pattern pattern;

    public RequiredPatternRule(
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
        boolean found = this.pattern.matcher(snippet).find();
        if (!found) {
            return new RuleVerdict(
                this.identifier,
                false,
                "Missing requirement for " + this.identifier + ": " + this.name
            );
        }
        return new RuleVerdict(
            this.identifier,
            true,
            "Requirement satisfied for " + this.identifier
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

