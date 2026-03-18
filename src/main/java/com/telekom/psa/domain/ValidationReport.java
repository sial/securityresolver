package com.telekom.psa.domain;

import java.util.Collections;
import java.util.List;

/**
 * Immutable validation report containing all rule verdicts.
 */
public final class ValidationReport implements Report {

    private final List<Verdict> verdicts;

    public ValidationReport(final List<Verdict> verdicts) {
        this.verdicts = Collections.unmodifiableList(verdicts);
    }

    @Override
    public List<Verdict> verdicts() {
        return this.verdicts;
    }

    @Override
    public long violations() {
        return this.verdicts.stream().filter(v -> !v.passed()).count();
    }

    @Override
    public long passes() {
        return this.verdicts.stream().filter(Verdict::passed).count();
    }
}

