package com.telekom.psa;

import com.telekom.psa.domain.Rule;
import com.telekom.psa.engine.Engine;
import com.telekom.psa.engine.Validator;
import com.telekom.psa.rule.Catalog;
import com.telekom.psa.rule.RuleCatalog;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.List;

/**
 * Wires the PSA rule catalog and validation engine into Spring context.
 */
@Configuration
public class PsaConfiguration {

    @Bean
    public Catalog catalog() {
        return new RuleCatalog(8);
    }

    @Bean
    public Engine engine(final Catalog catalog) {
        List<Rule> rules = catalog.rules();
        return new Validator(rules);
    }
}

