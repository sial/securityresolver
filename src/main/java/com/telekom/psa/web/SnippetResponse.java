package com.telekom.psa.web;

import com.telekom.psa.domain.Report;
import com.telekom.psa.domain.Verdict;
import java.util.List;

/**
 * Outgoing response payload after validation.
 */
public final class SnippetResponse {

    private final long violations;
    private final long passes;
    private final long total;
    private final List<VerdictDto> verdicts;

    public SnippetResponse(final Report report) {
        this.violations = report.violations();
        this.passes = report.passes();
        this.total = report.verdicts().size();
        this.verdicts = report.verdicts().stream()
            .map(VerdictDto::new)
            .toList();
    }

    public long violations() {
        return this.violations;
    }

    public long passes() {
        return this.passes;
    }

    public long total() {
        return this.total;
    }

    public List<VerdictDto> verdicts() {
        return this.verdicts;
    }

    /**
     * Single verdict serialized for the HTTP response.
     */
    public static final class VerdictDto {

        private final String rule;
        private final boolean passed;
        private final String reason;

        VerdictDto(final Verdict verdict) {
            this.rule = verdict.rule();
            this.passed = verdict.passed();
            this.reason = verdict.reason();
        }

        public String rule() {
            return this.rule;
        }

        public boolean passed() {
            return this.passed;
        }

        public String reason() {
            return this.reason;
        }
    }
}

