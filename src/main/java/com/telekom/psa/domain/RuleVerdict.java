package com.telekom.psa.domain;

/**
 * Immutable verdict produced after evaluating a PSA rule.
 */
public final class RuleVerdict implements Verdict {

    private final String rule;
    private final boolean passed;
    private final String reason;

    public RuleVerdict(final String rule, final boolean passed, final String reason) {
        this.rule = rule;
        this.passed = passed;
        this.reason = reason;
    }

    @Override
    public String rule() {
        return this.rule;
    }

    @Override
    public boolean passed() {
        return this.passed;
    }

    @Override
    public String reason() {
        return this.reason;
    }
}

