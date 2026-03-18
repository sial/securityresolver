package com.telekom.psa.rule;

import com.telekom.psa.domain.Rule;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Produces all PSA 3.06 Web Application security rules (Req 1 - Req 80).
 * Each rule maps to a pattern-based code snippet validator derived from the
 * Deutsche Telekom PSA document "3_06_Web_Applications_v8.0".
 */
public final class RuleCatalog implements Catalog {

    private final int edition;

    public RuleCatalog(final int edition) {
        this.edition = edition;
    }

    @Override
    public List<Rule> rules() {
        return List.of(
            // ===== 2. System Hardening =====
            // Req 1: Only required software may be used on the system
            new CompositePatternRule(
                "Req-01", "Only required software may be used on the system",
                "Detects debug or sample code left in production (debug mode flags, sample/test data, example endpoints)",
                List.of(
                    Pattern.compile("(?i)debug\\s*=\\s*true"),
                    Pattern.compile("(?i)DEBUG_MODE\\s*=\\s*true"),
                    Pattern.compile("(?i)app\\.debug\\s*=\\s*true"),
                    Pattern.compile("(?i)sample[-_]?data"),
                    Pattern.compile("(?i)test[-_]?data\\s*="),
                    Pattern.compile("(?i)example[-_]?(endpoint|route|controller)")
                )
            ),
            // Req 2: Features not required must be deactivated
            new CompositePatternRule(
                "Req-02", "Features not required must be deactivated",
                "Detects enabled debug features, development endpoints, or profiling left active",
                List.of(
                    Pattern.compile("(?i)enable[-_]?debug"),
                    Pattern.compile("(?i)devtools\\.enabled\\s*=\\s*true"),
                    Pattern.compile("(?i)spring\\.devtools"),
                    Pattern.compile("(?i)profiling\\s*=\\s*(true|on|enabled)"),
                    Pattern.compile("(?i)swagger[-_]?ui\\.enabled\\s*=\\s*true"),
                    Pattern.compile("(?i)actuator\\.enabled\\s*=\\s*true")
                )
            ),
            // Req 3: Software must be from trusted sources and checked for integrity
            new PatternRule(
                "Req-03", "Software must be from trusted sources and checked for integrity",
                "Detects dependency references to untrusted or unverified sources",
                Pattern.compile("(?i)(jitpack\\.io|raw\\.githubusercontent\\.com|http://)")
            ),
            // Req 4: SRI for external resources
            new CompositePatternRule(
                "Req-04", "External resources must use Subresource Integrity (SRI)",
                "Detects script/link tags loading external resources without integrity attribute",
                List.of(
                    Pattern.compile("(?i)<script[^>]+src\\s*=\\s*[\"']https?://(?!.*integrity)[^>]*>"),
                    Pattern.compile("(?i)<link[^>]+href\\s*=\\s*[\"']https?://(?!.*integrity)[^>]*>")
                )
            ),
            // ===== 3. System Update =====
            // Req 5: Security vulnerability support from supplier
            new PatternRule(
                "Req-05", "Software must be covered by security vulnerability support",
                "Detects references to deprecated or end-of-life software versions",
                Pattern.compile("(?i)(end[-_]?of[-_]?life|eol|deprecated[-_]?version|unsupported[-_]?version)")
            ),
            // Req 6: No end-of-life client-side technologies
            new CompositePatternRule(
                "Req-06", "Must not use end-of-life client-side technologies",
                "Detects Flash, Shockwave, ActiveX, Java applets or other obsolete client tech",
                List.of(
                    Pattern.compile("(?i)<object[^>]*type\\s*=\\s*[\"']application/x-shockwave-flash"),
                    Pattern.compile("(?i)<embed[^>]*type\\s*=\\s*[\"']application/x-shockwave-flash"),
                    Pattern.compile("(?i)\\.swf"),
                    Pattern.compile("(?i)ActiveXObject"),
                    Pattern.compile("(?i)<applet"),
                    Pattern.compile("(?i)<object[^>]*classid"),
                    Pattern.compile("(?i)shockwave|flash\\.embed")
                )
            ),
            // Req 7: Known vulnerabilities must be fixed
            new CompositePatternRule(
                "Req-07", "Known vulnerabilities must be fixed or protected against",
                "Detects TODO/FIXME annotations referencing security vulnerabilities",
                List.of(
                    Pattern.compile("(?i)(TODO|FIXME|HACK)\\s*:?\\s*(security|vuln|CVE|patch)"),
                    Pattern.compile("(?i)known[-_]?vulnerabilit(y|ies)")
                )
            ),
            // ===== 4. Protection of Data and Information =====
            // Req 8: Stored data protection
            new CompositePatternRule(
                "Req-08", "Stored data must be protected against unauthorized access",
                "Detects plaintext storage of passwords, secrets, or keys",
                List.of(
                    Pattern.compile("(?i)password\\s*=\\s*[\"'][^\"']+[\"']"),
                    Pattern.compile("(?i)(secret|api[-_]?key|private[-_]?key)\\s*=\\s*[\"'][^\"']+[\"']"),
                    Pattern.compile("(?i)credentials\\s*=\\s*[\"'][^\"']+[\"']"),
                    Pattern.compile("(?i)(jdbc|mysql|postgres|oracle)://[^\\s]+:[^\\s]+@")
                )
            ),
            // Req 9: Data in transit must be protected
            new CompositePatternRule(
                "Req-09", "Data in transit must be protected against unauthorized access",
                "Detects unencrypted transport protocols for sensitive data",
                List.of(
                    Pattern.compile("(?i)http://(?!localhost|127\\.0\\.0\\.1|\\[::1\\])"),
                    Pattern.compile("(?i)ftp://"),
                    Pattern.compile("(?i)telnet://"),
                    Pattern.compile("(?i)smtp://(?!localhost)")
                )
            ),
            // Req 10: TLS with server auth must be used
            new CompositePatternRule(
                "Req-10", "TLS with server authentication must be used for the web application",
                "Detects disabled TLS verification or insecure SSL configurations",
                List.of(
                    Pattern.compile("(?i)ssl[-_]?verify\\s*=\\s*(false|0|no|off)"),
                    Pattern.compile("(?i)verify\\s*=\\s*False"),
                    Pattern.compile("(?i)VERIFY_NONE"),
                    Pattern.compile("(?i)setHostnameVerifier\\s*\\("),
                    Pattern.compile("(?i)TrustAllCerts"),
                    Pattern.compile("(?i)InsecureTrustManager"),
                    Pattern.compile("(?i)X509TrustManager\\s*\\{[^}]*return\\s*;"),
                    Pattern.compile("(?i)checkServerTrusted\\s*\\([^)]*\\)\\s*\\{\\s*\\}")
                )
            ),
            // Req 11: HSTS header must be set
            new RequiredPatternRule(
                "Req-11", "HSTS header must be set",
                "Checks that Strict-Transport-Security header is configured",
                Pattern.compile("(?i)(Strict-Transport-Security|hsts|transport[-_]?security)")
            ),
            // Req 12: No sensitive data in URL parameters
            new CompositePatternRule(
                "Req-12", "Must not use URL parameters for sensitive data",
                "Detects sensitive data passed via GET parameters or URL query strings",
                List.of(
                    Pattern.compile("(?i)\\?.*password="),
                    Pattern.compile("(?i)\\?.*token="),
                    Pattern.compile("(?i)\\?.*secret="),
                    Pattern.compile("(?i)\\?.*api[-_]?key="),
                    Pattern.compile("(?i)\\?.*credit[-_]?card="),
                    Pattern.compile("(?i)\\?.*ssn="),
                    Pattern.compile("(?i)request\\.getParameter\\s*\\(\\s*[\"']password"),
                    Pattern.compile("(?i)@RequestParam[^)]*password"),
                    Pattern.compile("(?i)@GetMapping.*password")
                )
            ),
            // Req 13: No sensitive data stored client-side
            new CompositePatternRule(
                "Req-13", "Must not store sensitive data on the client side",
                "Detects storage of sensitive data in localStorage, sessionStorage, or persistent cookies",
                List.of(
                    Pattern.compile("(?i)localStorage\\.setItem\\s*\\([^)]*password"),
                    Pattern.compile("(?i)localStorage\\.setItem\\s*\\([^)]*token"),
                    Pattern.compile("(?i)localStorage\\.setItem\\s*\\([^)]*secret"),
                    Pattern.compile("(?i)localStorage\\.setItem\\s*\\([^)]*credit"),
                    Pattern.compile("(?i)document\\.cookie\\s*=.*password"),
                    Pattern.compile("(?i)document\\.cookie\\s*=.*expires\\s*=.*password")
                )
            ),
            // Req 14: Prevent caching of sensitive data
            new CompositePatternRule(
                "Req-14", "Must prevent caching of sensitive data",
                "Detects fat GET requests (GET with request body) or missing cache control headers",
                List.of(
                    Pattern.compile("(?i)@GetMapping[^)]*\\)\\s*[^{]*@RequestBody"),
                    Pattern.compile("(?i)GET.*requestBody"),
                    Pattern.compile("(?i)cache[-_]?control\\s*[:=]\\s*[\"']?public")
                )
            ),
            // Req 15: Error messages must not reveal sensitive info
            new CompositePatternRule(
                "Req-15", "Error messages must not contain implementation details",
                "Detects stack traces, SQL errors, or version info exposed to users",
                List.of(
                    Pattern.compile("(?i)printStackTrace\\s*\\("),
                    Pattern.compile("(?i)e\\.getMessage\\s*\\(\\s*\\)"),
                    Pattern.compile("(?i)exception\\.toString\\s*\\("),
                    Pattern.compile("(?i)server\\.error\\.include[-_]?stacktrace\\s*=\\s*always"),
                    Pattern.compile("(?i)sql[-_]?error|mysql[-_]?error|pg[-_]?error"),
                    Pattern.compile("(?i)X-Powered-By"),
                    Pattern.compile("(?i)Server:\\s*(Apache|nginx|Tomcat|IIS)")
                )
            ),
            // ===== 5. Protection of Availability and Integrity =====
            // Req 16: Server-side input validation
            new CompositePatternRule(
                "Req-16", "Server-side input validation for all client data",
                "Detects unvalidated direct use of request parameters in sensitive operations",
                List.of(
                    Pattern.compile("(?i)request\\.getParameter\\s*\\([^)]+\\)\\s*;\\s*$", Pattern.MULTILINE),
                    Pattern.compile("(?i)\\$_GET\\["),
                    Pattern.compile("(?i)\\$_POST\\["),
                    Pattern.compile("(?i)\\$_REQUEST\\["),
                    Pattern.compile("(?i)request\\.query\\.[a-z]+\\s*(?!.*validat)")
                )
            ),
            // Req 17: Data from other systems must be treated as untrusted
            new PatternRule(
                "Req-17", "All external system data must be treated as untrustworthy",
                "Detects direct trust of external system data without validation",
                Pattern.compile("(?i)trusted[-_]?source\\s*=\\s*(true|yes)")
            ),
            // Req 18: No direct file access via user input
            new CompositePatternRule(
                "Req-18", "Must not use user input for direct file/directory access",
                "Detects path traversal risks and direct file access from user input",
                List.of(
                    Pattern.compile("(?i)new\\s+File\\s*\\(\\s*request\\."),
                    Pattern.compile("(?i)new\\s+File\\s*\\(.*getParameter"),
                    Pattern.compile("(?i)Paths\\.get\\s*\\(.*getParameter"),
                    Pattern.compile("(?i)\\.\\.[\\\\/]"),
                    Pattern.compile("(?i)file_get_contents\\s*\\(\\s*\\$_(GET|POST|REQUEST)"),
                    Pattern.compile("(?i)include\\s*\\(\\s*\\$_(GET|POST|REQUEST)"),
                    Pattern.compile("(?i)require\\s*\\(\\s*\\$_(GET|POST|REQUEST)")
                )
            ),
            // Req 19: Secure deserialization
            new CompositePatternRule(
                "Req-19", "Deserialized objects must not contain untrusted input",
                "Detects insecure deserialization patterns",
                List.of(
                    Pattern.compile("(?i)ObjectInputStream\\s*\\("),
                    Pattern.compile("(?i)readObject\\s*\\(\\s*\\)"),
                    Pattern.compile("(?i)XMLDecoder\\s*\\("),
                    Pattern.compile("(?i)unserialize\\s*\\("),
                    Pattern.compile("(?i)pickle\\.load(s)?\\s*\\("),
                    Pattern.compile("(?i)yaml\\.load\\s*\\((?!.*Loader\\s*=\\s*SafeLoader)"),
                    Pattern.compile("(?i)JsonParser\\.Feature\\.USE_GETTERS_AS_SETTERS")
                )
            ),
            // Req 20: File upload security
            new CompositePatternRule(
                "Req-20", "File uploads must be validated and processed securely",
                "Detects missing file upload validation (extension, size, content-type checks)",
                List.of(
                    Pattern.compile("(?i)multipart.*(?!.*content[-_]?type)(?!.*valid)(?!.*check)(?!.*size)"),
                    Pattern.compile("(?i)getOriginalFilename\\s*\\(\\s*\\)(?!.*sanitiz)(?!.*valid)"),
                    Pattern.compile("(?i)move_uploaded_file\\s*\\((?!.*valid)")
                )
            ),
            // Req 21: Content-Type and X-Content-Type-Options headers
            new PatternRule(
                "Req-21", "Output must specify Content-Type and X-Content-Type-Options: nosniff",
                "Detects missing nosniff header configuration",
                Pattern.compile("(?i)X-Content-Type-Options\\s*[:=]\\s*[\"']?(?!nosniff)")
            ),
            // Req 22: XSS prevention via HTML encoding
            new CompositePatternRule(
                "Req-22", "Must HTML-encode meta characters to prevent XSS",
                "Detects unescaped output of user input into HTML",
                List.of(
                    Pattern.compile("(?i)\\$\\{[^}]*request"),
                    Pattern.compile("(?i)out\\.print(ln)?\\s*\\(\\s*request\\."),
                    Pattern.compile("(?i)response\\.getWriter\\(\\)\\.write\\s*\\(\\s*request\\."),
                    Pattern.compile("(?i)<%=\\s*request\\."),
                    Pattern.compile("(?i)innerHTML\\s*=\\s*(?!.*escap)(?!.*encod)(?!.*sanit)"),
                    Pattern.compile("(?i)document\\.write\\s*\\((?!.*escap)(?!.*encod)")
                )
            ),
            // Req 23: Context-specific escaping outside HTML
            new CompositePatternRule(
                "Req-23", "Context-specific escaping required for non-HTML output",
                "Detects unescaped output in JavaScript, URL, or CSS contexts",
                List.of(
                    Pattern.compile("(?i)<script>[^<]*\\+\\s*(?:request|params|input)"),
                    Pattern.compile("(?i)url\\s*\\(\\s*[\"']?\\s*\\+\\s*(?:request|params|input)"),
                    Pattern.compile("(?i)style\\s*=\\s*[\"'][^\"']*\\+\\s*(?:request|params|input)")
                )
            ),
            // Req 24: DOM-based XSS prevention
            new CompositePatternRule(
                "Req-24", "DOM changes based on input must prevent DOM-based XSS",
                "Detects unsafe DOM manipulation methods with user input",
                List.of(
                    Pattern.compile("(?i)element\\.innerHTML\\s*="),
                    Pattern.compile("(?i)element\\.outerHTML\\s*="),
                    Pattern.compile("(?i)document\\.write\\s*\\("),
                    Pattern.compile("(?i)document\\.writeln\\s*\\("),
                    Pattern.compile("(?i)\\.innerHTML\\s*=\\s*.*(?:location|document\\.URL|document\\.referrer)")
                )
            ),
            // Req 25: Tag filter for WYSIWYG/markup input
            new PatternRule(
                "Req-25", "WYSIWYG or markup input must use tag filter against XSS",
                "Detects WYSIWYG editors without sanitization configuration",
                Pattern.compile("(?i)(ckeditor|tinymce|quill|froala|wysiwyg)(?!.*sanitiz)(?!.*filter)(?!.*whitelist)")
            ),
            // Req 26: SQL/NoSQL injection prevention
            new CompositePatternRule(
                "Req-26", "Must prevent SQL/NoSQL injection with parameterized queries",
                "Detects string concatenation in SQL/NoSQL queries",
                List.of(
                    Pattern.compile("(?i)[\"']\\s*\\+\\s*.*\\+\\s*[\"'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)"),
                    Pattern.compile("(?i)(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*[\"']\\s*\\+"),
                    Pattern.compile("(?i)createQuery\\s*\\([^)]*\\+"),
                    Pattern.compile("(?i)executeQuery\\s*\\([^)]*\\+"),
                    Pattern.compile("(?i)executeUpdate\\s*\\([^)]*\\+"),
                    Pattern.compile("(?i)\\$where\\s*:"),
                    Pattern.compile("(?i)db\\.collection.*find\\s*\\(.*\\$"),
                    Pattern.compile("(?i)raw_input.*execute"),
                    Pattern.compile("(?i)string\\.Format.*SQL|String\\.format.*(?:SELECT|INSERT|UPDATE|DELETE)")
                )
            ),
            // Req 27: XML/XPath/XXE injection prevention
            new CompositePatternRule(
                "Req-27", "Must prevent XML/XPath/XXE injection",
                "Detects XML parsers without external entity protection or XPath with user input",
                List.of(
                    Pattern.compile("(?i)FEATURE_SECURE_PROCESSING\\s*,\\s*false"),
                    Pattern.compile("(?i)setFeature\\s*\\([^)]*external[-_]?general[-_]?entities[^)]*true"),
                    Pattern.compile("(?i)setFeature\\s*\\([^)]*external[-_]?parameter[-_]?entities[^)]*true"),
                    Pattern.compile("(?i)<!DOCTYPE[^>]*<!ENTITY"),
                    Pattern.compile("(?i)DISALLOW_DOCTYPE_DECL\\s*,\\s*false"),
                    Pattern.compile("(?i)XPathExpression.*\\+.*request"),
                    Pattern.compile("(?i)xpath\\.evaluate\\s*\\([^)]*\\+")
                )
            ),
            // Req 28: No shell/code execution from input
            new CompositePatternRule(
                "Req-28", "Must not create shell or eval commands from input data",
                "Detects command injection and eval usage with user input",
                List.of(
                    Pattern.compile("(?i)Runtime\\.getRuntime\\(\\)\\.exec\\s*\\("),
                    Pattern.compile("(?i)ProcessBuilder\\s*\\(.*request"),
                    Pattern.compile("(?i)ProcessBuilder\\s*\\(.*getParameter"),
                    Pattern.compile("(?i)eval\\s*\\("),
                    Pattern.compile("(?i)exec\\s*\\(.*request"),
                    Pattern.compile("(?i)system\\s*\\(.*\\$"),
                    Pattern.compile("(?i)os\\.system\\s*\\("),
                    Pattern.compile("(?i)subprocess\\.(call|run|Popen)\\s*\\(.*input"),
                    Pattern.compile("(?i)child_process"),
                    Pattern.compile("(?i)new\\s+Function\\s*\\(")
                )
            ),
            // Req 29: HTTP header injection prevention
            new CompositePatternRule(
                "Req-29", "HTTP headers from input must be validated for CR/LF injection",
                "Detects unvalidated user input in HTTP response headers",
                List.of(
                    Pattern.compile("(?i)response\\.setHeader\\s*\\([^,]+,\\s*request\\."),
                    Pattern.compile("(?i)response\\.addHeader\\s*\\([^,]+,\\s*request\\."),
                    Pattern.compile("(?i)response\\.setHeader\\s*\\([^,]+,\\s*.*getParameter"),
                    Pattern.compile("(?i)header\\s*\\(\\s*[\"'].*\\$_(GET|POST|REQUEST)")
                )
            ),
            // Req 30: Email injection prevention
            new CompositePatternRule(
                "Req-30", "Must prevent email injection into mail server",
                "Detects email header injection risks from user input",
                List.of(
                    Pattern.compile("(?i)mail\\s*\\(.*\\$_(GET|POST|REQUEST)"),
                    Pattern.compile("(?i)setSubject\\s*\\(\\s*request\\."),
                    Pattern.compile("(?i)setFrom\\s*\\(\\s*request\\."),
                    Pattern.compile("(?i)addRecipient.*request\\.getParameter"),
                    Pattern.compile("(?i)\\bCC:\\s*.*\\$_(GET|POST)")
                )
            ),
            // Req 31: No input data for URL formation / prevent SSRF
            new CompositePatternRule(
                "Req-31", "Must not use input data to form redirect URLs (prevent SSRF)",
                "Detects open redirects and SSRF patterns",
                List.of(
                    Pattern.compile("(?i)response\\.sendRedirect\\s*\\(\\s*request\\."),
                    Pattern.compile("(?i)redirect\\s*:\\s*.*request\\.getParameter"),
                    Pattern.compile("(?i)new\\s+URL\\s*\\(\\s*request\\."),
                    Pattern.compile("(?i)HttpURLConnection.*request\\.getParameter"),
                    Pattern.compile("(?i)RestTemplate.*request\\.getParameter"),
                    Pattern.compile("(?i)WebClient.*request\\.getParameter"),
                    Pattern.compile("(?i)header\\s*\\(\\s*[\"']Location.*\\$_(GET|POST)")
                )
            ),
            // Req 32: Anti-spam for unauthenticated actions
            new PatternRule(
                "Req-32", "Unauthenticated email/SMS/form actions must prevent misuse",
                "Detects email send or contact form endpoints without rate limiting or CAPTCHA",
                Pattern.compile("(?i)(send[-_]?email|send[-_]?sms|contact[-_]?form).*(?!.*captcha)(?!.*rate[-_]?limit)")
            ),
            // ===== 6. Authentication and Authorization =====
            // Req 33: Auth required for protected functions and data
            new CompositePatternRule(
                "Req-33", "Protected functions require authentication and authorization",
                "Detects endpoints with sensitive operations missing auth annotations",
                List.of(
                    Pattern.compile("(?i)permitAll\\s*\\(\\s*\\).*(/admin|/delete|/update|/config)"),
                    Pattern.compile("(?i)\\.anonymous\\(\\).*(/admin|/delete|/modify)"),
                    Pattern.compile("(?i)@RequestMapping.*/admin(?!.*@Secured)(?!.*@PreAuthorize)(?!.*@RolesAllowed)")
                )
            ),
            // Req 34: Least privilege for users and applications
            new CompositePatternRule(
                "Req-34", "Permissions must follow least privilege principle",
                "Detects overly broad permissions or running as root/admin",
                List.of(
                    Pattern.compile("(?i)chmod\\s+777"),
                    Pattern.compile("(?i)grant\\s+all\\s+privileges", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("(?i)run[-_]?as[-_]?root\\s*=\\s*true"),
                    Pattern.compile("(?i)user\\s*:\\s*root"),
                    Pattern.compile("(?i)GRANT\\s+ALL\\s+ON"),
                    Pattern.compile("(?i)securityContext.*runAsUser:\\s*0")
                )
            ),
            // Req 35: Unique user identification
            new PatternRule(
                "Req-35", "User accounts must ensure unique identification",
                "Detects shared or group account patterns",
                Pattern.compile("(?i)(shared[-_]?account|group[-_]?account|generic[-_]?user|guest[-_]?login)")
            ),
            // Req 36: Delete or disable predefined user accounts
            new CompositePatternRule(
                "Req-36", "Predefined unused user accounts must be deleted or disabled",
                "Detects references to default/predefined accounts left enabled",
                List.of(
                    Pattern.compile("(?i)username\\s*=\\s*[\"']admin[\"']"),
                    Pattern.compile("(?i)username\\s*=\\s*[\"']guest[\"']"),
                    Pattern.compile("(?i)username\\s*=\\s*[\"']test[\"']"),
                    Pattern.compile("(?i)user\\s*=\\s*[\"']sa[\"']"),
                    Pattern.compile("(?i)default[-_]?password"),
                    Pattern.compile("(?i)password\\s*=\\s*[\"'](admin|password|guest|test|123|root)[\"']")
                )
            ),
            // Req 37: Anti-automation for registration
            new PatternRule(
                "Req-37", "Internet-facing registration must prevent automated registration",
                "Detects registration endpoints without CAPTCHA or anti-automation",
                Pattern.compile("(?i)(register|signup|sign[-_]?up)(?!.*captcha)(?!.*recaptcha)(?!.*turnstile)")
            ),
            // Req 38: Multi-factor authentication
            new PatternRule(
                "Req-38", "User accounts must use multi-factor authentication",
                "Detects single-factor authentication without MFA references",
                Pattern.compile("(?i)mfa\\s*=\\s*(false|off|disabled)|two[-_]?factor\\s*=\\s*(false|off|disabled)")
            ),
            // Req 39: Privileged accounts must use phishing-resistant MFA
            new PatternRule(
                "Req-39", "Privileged accounts must use phishing-resistant MFA",
                "Detects admin/privileged login without enhanced MFA",
                Pattern.compile("(?i)(admin|privileged|root)[-_]?mfa\\s*=\\s*(false|off|disabled)")
            ),
            // Req 40: Re-authentication for critical actions
            new PatternRule(
                "Req-40", "Must re-authenticate for critical data changes",
                "Detects password change or critical action without current password verification",
                Pattern.compile("(?i)(change[-_]?password|update[-_]?email|delete[-_]?account)(?!.*current[-_]?password)(?!.*re[-_]?auth)")
            ),
            // ===== 7. Protecting Sessions =====
            // Req 41: Session ID minimum length 120 bit
            new PatternRule(
                "Req-41", "Session ID must be at least 120 bit and random",
                "Detects weak or short session ID generation",
                Pattern.compile("(?i)(session[-_]?id[-_]?length|sid[-_]?length)\\s*=\\s*[0-9]{1,2}[^0-9]")
            ),
            // Req 42: Stateless token (JWT) integrity
            new CompositePatternRule(
                "Req-42", "JWT/stateless tokens must prevent manipulation and replay",
                "Detects insecure JWT configurations (alg:none, no expiration, no signature verification)",
                List.of(
                    Pattern.compile("(?i)\"alg\"\\s*:\\s*\"none\""),
                    Pattern.compile("(?i)alg\\s*=\\s*[\"']none[\"']"),
                    Pattern.compile("(?i)jwt\\.decode\\s*\\([^)]*verify\\s*=\\s*false"),
                    Pattern.compile("(?i)setSigningKey\\s*\\(\\s*[\"'][\"']\\s*\\)"),
                    Pattern.compile("(?i)unsecuredJwt|UnsecuredJwsAlgorithm"),
                    Pattern.compile("(?i)ignoreExpiration\\s*=\\s*true")
                )
            ),
            // Req 43: Session IDs must not be in URL
            new CompositePatternRule(
                "Req-43", "Session identifiers must not be in URL parameters",
                "Detects session IDs passed via URL parameters",
                List.of(
                    Pattern.compile("(?i)\\?.*jsessionid="),
                    Pattern.compile("(?i)\\?.*session[-_]?id="),
                    Pattern.compile("(?i)\\?.*sid="),
                    Pattern.compile("(?i)\\?.*token="),
                    Pattern.compile("(?i)url[-_]?rewriting\\s*=\\s*(true|enabled)")
                )
            ),
            // Req 44: Session tokens must not be stored persistently
            new CompositePatternRule(
                "Req-44", "Session tokens must not be stored persistently in browser",
                "Detects persistent storage of session tokens (localStorage, persistent cookies)",
                List.of(
                    Pattern.compile("(?i)localStorage\\.setItem\\s*\\([^)]*session"),
                    Pattern.compile("(?i)localStorage\\.setItem\\s*\\([^)]*token"),
                    Pattern.compile("(?i)expires\\s*=.*session[-_]?(id|token)"),
                    Pattern.compile("(?i)max[-_]?age\\s*=.*session")
                )
            ),
            // Req 45: Secure attribute in session cookie
            new PatternRule(
                "Req-45", "Session cookie must have Secure attribute",
                "Detects session cookie configuration without Secure flag",
                Pattern.compile("(?i)cookie.*secure\\s*=\\s*(false|0|no)")
            ),
            // Req 46: HttpOnly attribute in session cookie
            new PatternRule(
                "Req-46", "Session cookie must have HttpOnly attribute",
                "Detects session cookie configuration without HttpOnly flag",
                Pattern.compile("(?i)(httpOnly|http[-_]?only)\\s*=\\s*(false|0|no)")
            ),
            // Req 47: Domain attribute must not be set in session cookie
            new PatternRule(
                "Req-47", "Session cookie must not set Domain attribute",
                "Detects session cookie with explicit domain attribute set broadly",
                Pattern.compile("(?i)cookie.*domain\\s*=\\s*[\"']\\..*[\"']")
            ),
            // Req 48: Restrictive path attribute in session cookie
            new PatternRule(
                "Req-48", "Session cookie path must be restrictive",
                "Detects session cookie with overly broad path=/",
                Pattern.compile("(?i)session.*cookie.*path\\s*=\\s*[\"']/[\"']")
            ),
            // Req 49: Only one active session per user
            new PatternRule(
                "Req-49", "Only one session per user account at a time",
                "Detects concurrent session configuration allowing unlimited sessions",
                Pattern.compile("(?i)maximum[-_]?sessions\\s*=\\s*(-1|unlimited|0)")
            ),
            // Req 50: Logout function
            new PatternRule(
                "Req-50", "User must be able to logout at any time",
                "Detects disabled or missing logout functionality",
                Pattern.compile("(?i)logout\\s*=\\s*(disabled|false|off)")
            ),
            // Req 51: SSO logout must terminate both sessions
            new PatternRule(
                "Req-51", "SSO logout must terminate both web app and SSO portal sessions",
                "Detects SSO integration without single logout (SLO) support",
                Pattern.compile("(?i)sso.*(?!.*single[-_]?logout)(?!.*slo)(?!.*back[-_]?channel[-_]?logout)")
            ),
            // Req 52: SSO portal logout must terminate web app session
            new PatternRule(
                "Req-52", "SSO portal logout must also terminate web app session",
                "Detects SSO without back-channel logout support",
                Pattern.compile("(?i)sso\\.back[-_]?channel[-_]?logout\\s*=\\s*(false|disabled)")
            ),
            // Req 53: Session timeout after inactivity
            new CompositePatternRule(
                "Req-53", "Session timeout after inactivity period",
                "Detects disabled session timeout or excessively long timeout values",
                List.of(
                    Pattern.compile("(?i)session[-_]?timeout\\s*=\\s*(0|-1|disabled|never)"),
                    Pattern.compile("(?i)max[-_]?inactive[-_]?interval\\s*=\\s*-1"),
                    Pattern.compile("(?i)timeout\\s*=\\s*[0-9]{6,}")
                )
            ),
            // Req 54: Session invalidation on logout/timeout
            new PatternRule(
                "Req-54", "Session must be invalidated server-side on logout/timeout",
                "Detects client-only logout without server session invalidation",
                Pattern.compile("(?i)logout.*(?:cookie\\.delete|localStorage\\.remove)(?!.*session\\.invalidat)(?!.*revoke)")
            ),
            // Req 55: CSRF protection
            new CompositePatternRule(
                "Req-55", "Must use CSRF protection mechanism",
                "Detects disabled CSRF protection",
                List.of(
                    Pattern.compile("(?i)csrf\\(\\)\\.disable\\(\\)"),
                    Pattern.compile("(?i)csrf\\.enabled\\s*=\\s*(false|off)"),
                    Pattern.compile("(?i)@EnableWebSecurity(?!.*csrf)"),
                    Pattern.compile("(?i)CSRF_PROTECTION\\s*=\\s*(false|off|disabled)")
                )
            ),
            // Req 56: Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
            new PatternRule(
                "Req-56", "Must prevent clickjacking (X-Frame-Options or frame-ancestors)",
                "Detects disabled frame options or missing clickjacking protection",
                Pattern.compile("(?i)(frame[-_]?options|x[-_]?frame[-_]?options)\\s*=\\s*(disabled|off|false|ALLOW)")
            ),
            // Req 57: Restrictive CORS
            new CompositePatternRule(
                "Req-57", "Cross-domain access (CORS) must be defined restrictively",
                "Detects wildcard CORS or overly permissive cross-origin configurations",
                List.of(
                    Pattern.compile("(?i)Access-Control-Allow-Origin\\s*:\\s*\\*"),
                    Pattern.compile("(?i)allowedOrigins\\s*\\(\\s*[\"']\\*[\"']"),
                    Pattern.compile("(?i)cors\\.allowed[-_]?origins\\s*=\\s*\\*"),
                    Pattern.compile("(?i)\\.allowedOrigins\\(\"\\*\"\\)"),
                    Pattern.compile("(?i)@CrossOrigin\\s*$", Pattern.MULTILINE),
                    Pattern.compile("(?i)postMessage\\s*\\([^)]*,\\s*[\"']\\*[\"']")
                )
            ),
            // ===== 8. Authentication Parameter Password =====
            // Req 58: Password minimum 12 characters, 3 of 4 categories
            new CompositePatternRule(
                "Req-58", "Password must be at least 12 chars with 3 of 4 character categories",
                "Detects weak password policy configurations allowing short passwords",
                List.of(
                    Pattern.compile("(?i)min[-_]?(password[-_]?)?length\\s*=\\s*([1-9]|1[01])\\b"),
                    Pattern.compile("(?i)password[-_]?min[-_]?length\\s*=\\s*([1-9]|1[01])\\b"),
                    Pattern.compile("(?i)PASSWORD_MIN_LENGTH\\s*=\\s*([1-9]|1[01])\\b")
                )
            ),
            // Req 59: Technical account password min 30 chars
            new PatternRule(
                "Req-59", "Technical account password must be at least 30 characters",
                "Detects technical/service account password policies with less than 30 char minimum",
                Pattern.compile("(?i)(technical|service|m2m)[-_]?.*password[-_]?min[-_]?length\\s*=\\s*([1-9]|[12][0-9])\\b")
            ),
            // Req 60: User must choose own password during registration
            new PatternRule(
                "Req-60", "User must set own password at registration or change initial password immediately",
                "Detects hardcoded initial passwords in registration flows",
                Pattern.compile("(?i)(initial[-_]?password|default[-_]?password)\\s*=\\s*[\"'][^\"']+[\"']")
            ),
            // Req 61: Users must be able to change password anytime
            new PatternRule(
                "Req-61", "Users must be able to change password at any time",
                "Detects disabled password change functionality",
                Pattern.compile("(?i)allow[-_]?password[-_]?change\\s*=\\s*(false|no|0)")
            ),
            // Req 62: Password must be changed after 12 months
            new PatternRule(
                "Req-62", "Password must expire after 12 months maximum",
                "Detects disabled password expiration or expiration longer than 365 days",
                Pattern.compile("(?i)password[-_]?(expir|max[-_]?age).*=\\s*(never|disabled|false|0|-1|[4-9][0-9]{2,})")
            ),
            // Req 63: Prevent reuse of previous passwords
            new PatternRule(
                "Req-63", "Must prevent reuse of previous passwords",
                "Detects disabled password history or history count of 0",
                Pattern.compile("(?i)password[-_]?history\\s*=\\s*(0|disabled|false|off|none)")
            ),
            // Req 64: Password reset function protected against misuse
            new PatternRule(
                "Req-64", "Password reset must be protected against misuse",
                "Detects password reset without rate limiting or security questions",
                Pattern.compile("(?i)(password[-_]?reset|forgot[-_]?password)(?!.*rate[-_]?limit)(?!.*captcha)(?!.*security[-_]?question)(?!.*token)")
            ),
            // Req 65: Brute force protection for password login
            new CompositePatternRule(
                "Req-65", "Must protect against brute force and dictionary attacks",
                "Detects login without account lockout or rate limiting",
                List.of(
                    Pattern.compile("(?i)account[-_]?lockout\\s*=\\s*(disabled|false|off|0)"),
                    Pattern.compile("(?i)max[-_]?attempts\\s*=\\s*(0|-1|unlimited)"),
                    Pattern.compile("(?i)login[-_]?rate[-_]?limit\\s*=\\s*(disabled|false|off)")
                )
            ),
            // Req 66: Passwords must be stored using password hashing
            new CompositePatternRule(
                "Req-66", "Passwords must be stored using secure password hashing",
                "Detects plaintext password storage, reversible encryption, or weak hashing for passwords",
                List.of(
                    Pattern.compile("(?i)password.*=.*base64"),
                    Pattern.compile("(?i)MD5.*password|password.*MD5"),
                    Pattern.compile("(?i)SHA1.*password|password.*SHA1"),
                    Pattern.compile("(?i)password.*AES.*encrypt"),
                    Pattern.compile("(?i)store[-_]?password[-_]?plain"),
                    Pattern.compile("(?i)password.*rot13"),
                    Pattern.compile("(?i)(?<!b)crypt\\s*\\(\\s*password", Pattern.CASE_INSENSITIVE)
                )
            ),
            // Req 67: Initial passwords and activation tokens must be protected
            new PatternRule(
                "Req-67", "Initial passwords and activation tokens must be protected against brute force",
                "Detects short or predictable activation tokens",
                Pattern.compile("(?i)(activation[-_]?token|initial[-_]?token)[-_]?length\\s*=\\s*([1-9]|1[0-4])\\b")
            ),
            // Req 68: Failed login must not reveal which credential was wrong
            new CompositePatternRule(
                "Req-68", "Failed login must not reveal which credential was incorrect",
                "Detects error messages that distinguish between wrong username and wrong password",
                List.of(
                    Pattern.compile("(?i)[\"'](?:user|username|account)\\s*(?:not\\s*found|does\\s*not\\s*exist|invalid|unknown)[\"']"),
                    Pattern.compile("(?i)[\"'](?:incorrect|wrong|invalid)\\s*password[\"']"),
                    Pattern.compile("(?i)[\"']no\\s*(?:such\\s*)?user[\"']"),
                    Pattern.compile("(?i)[\"']password\\s*(?:is\\s*)?incorrect[\"']")
                )
            ),
            // Req 69: Passwords must not be displayed in plain text during input
            new CompositePatternRule(
                "Req-69", "Passwords must not be displayed in plain text during input",
                "Detects password input fields without type=password masking",
                List.of(
                    Pattern.compile("(?i)<input[^>]*name\\s*=\\s*[\"']password[\"'][^>]*type\\s*=\\s*[\"']text[\"']"),
                    Pattern.compile("(?i)<input[^>]*type\\s*=\\s*[\"']text[\"'][^>]*name\\s*=\\s*[\"']password[\"']"),
                    Pattern.compile("(?i)password.*type\\s*=\\s*[\"']text[\"']")
                )
            ),
            // ===== 9. Content Management Systems =====
            // Req 70: CMS editing environment not accessible from Internet
            new PatternRule(
                "Req-70", "CMS editing environment must not be accessible from Internet",
                "Detects CMS admin panels exposed to public access",
                Pattern.compile("(?i)(wp-admin|/admin|/cms[-_]?admin|/editor).*permitAll|public.*(/wp-admin|/admin)")
            ),
            // Req 71: CMS must support multi-stage publication with role separation
            new PatternRule(
                "Req-71", "CMS must support multi-stage publication with role separation",
                "Informational rule - detects CMS without role-based access control",
                Pattern.compile("(?i)cms[-_]?roles\\s*=\\s*(disabled|none|false)")
            ),
            // Req 72: CMS content assignment to specific editors
            new PatternRule(
                "Req-72", "CMS must assign content exclusively to specific editors/groups",
                "Informational rule for CMS content isolation",
                Pattern.compile("(?i)cms[-_]?content[-_]?isolation\\s*=\\s*(disabled|false)")
            ),
            // Req 73: Unpublished content must not be viewable
            new PatternRule(
                "Req-73", "Unpublished CMS content must not be viewable before publication date",
                "Detects draft content accessible without authentication",
                Pattern.compile("(?i)(draft|unpublished).*public|permitAll.*(draft|unpublished)")
            ),
            // Req 74: CMS must restrict active content and scripting
            new PatternRule(
                "Req-74", "CMS must restrict active content and scripting in created content",
                "Detects CMS allowing unrestricted script execution in content",
                Pattern.compile("(?i)cms[-_]?allow[-_]?scripts\\s*=\\s*(true|all|unrestricted)")
            ),
            // Req 75: CMS preview must be access controlled
            new PatternRule(
                "Req-75", "CMS preview must be protected from unauthorized access",
                "Detects public preview endpoints",
                Pattern.compile("(?i)preview.*(?:public|permitAll|anonymous)")
            ),
            // ===== 10. Logging =====
            // Req 76: Security-relevant events must be logged
            new CompositePatternRule(
                "Req-76", "Security-relevant events must be logged",
                "Detects disabled security event logging or audit logging",
                List.of(
                    Pattern.compile("(?i)audit[-_]?log(ging)?\\s*=\\s*(disabled|false|off|none)"),
                    Pattern.compile("(?i)security[-_]?log(ging)?\\s*=\\s*(disabled|false|off|none)"),
                    Pattern.compile("(?i)login[-_]?log(ging)?\\s*=\\s*(disabled|false|off)")
                )
            ),
            // Req 77: Retention and deletion periods for local log data
            new PatternRule(
                "Req-77", "Local logging data must observe retention and deletion periods",
                "Detects log retention configured beyond 90 days or set to unlimited",
                Pattern.compile("(?i)log[-_]?retention[-_]?days\\s*=\\s*([1-9][0-9]{2,}|unlimited|never|-1)")
            ),
            // Req 78: Forward logs to log server immediately
            new PatternRule(
                "Req-78", "Security logs must be forwarded to a log server immediately",
                "Detects disabled or delayed log forwarding",
                Pattern.compile("(?i)log[-_]?forward(ing)?\\s*=\\s*(disabled|false|off|none)")
            ),
            // Req 79: Retention periods on log server
            new PatternRule(
                "Req-79", "Log server must observe retention and deletion periods",
                "Detects log server retention beyond 90 days or set to unlimited",
                Pattern.compile("(?i)log[-_]?server[-_]?retention\\s*=\\s*(unlimited|never|-1)")
            ),
            // Req 80: Logs must be provided to SIEM in near-real-time
            new PatternRule(
                "Req-80", "Security logs must be provided to SIEM in near-real-time",
                "Detects disabled SIEM integration or delayed log delivery",
                Pattern.compile("(?i)siem[-_]?(integration|forward)\\s*=\\s*(disabled|false|off|none)")
            )
        );
    }
}

