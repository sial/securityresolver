package com.telekom.psa.web;

import com.telekom.psa.domain.Report;
import com.telekom.psa.engine.Engine;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller that receives code snippets and validates them against PSA rules.
 */
@RestController
public final class ValidationController implements Endpoint {

    private final Engine engine;

    public ValidationController(final Engine engine) {
        this.engine = engine;
    }

    @Override
    @PostMapping("/validate")
    public SnippetResponse validate(@RequestBody final SnippetRequest request) {
        Report report = this.engine.validate(request.snippet());
        return new SnippetResponse(report);
    }
}

