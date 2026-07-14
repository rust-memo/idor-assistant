# IDOR/BOLA Assistant for Burp Suite

IDOR/BOLA Assistant is an evidence-driven access-control workbench built on Burp's Montoya API. It discovers object references passively, associates observed objects with captured test identities, and runs controlled owner-versus-other-identity comparisons without treating passive evidence as a vulnerability.

Passive discovery never sends requests. Batch testing is restricted to `GET` and `HEAD`, every active request must remain in Burp Target Scope, and state-changing requests require a separate manual confirmation.

## Highlights in v3.1

- Manages any number of identity profiles with role or tenant labels.
- Captures selected authentication headers and session-bound CSRF/XSRF values.
- Keeps profiles in memory by default. Optional Burp-project persistence requires an explicit warning acknowledgement.
- Retains up to 20 distinct observations per endpoint/reference instead of replacing them with the latest request.
- Infers an observation's owner when its captured authentication matches exactly one profile.
- Detects observed references in paths, URL/form parameters, JSON, GraphQL variables and inline arguments, XML elements and attributes, multipart data, cookies, and allowlisted headers.
- Uses evidence-qualified discovery: generic IDs, list/search routes, identity headers, session cookies, telemetry, pagination, and symbolic GraphQL variables no longer become normal candidates from one weak signal.
- Places reviewable low-evidence discoveries in **Suppressed** without highlighting Proxy traffic. Repeated distinct observed IDs can promote a suppressed endpoint.
- Supports endpoint- or host-scoped **Mark false positive** rules and reversible allow rules. Rules store selectors only, never raw IDs or HTTP messages.
- Uses observed IDs only. It does not guess adjacent values, enumerate identifiers, or brute-force objects.
- Compares status, content type, authentication barriers, redirects, normalized JSON/XML/HTML, object identity, sensitive fields, and owner-baseline stability.
- Runs sequential read-only matrices with a default budget of 20 HTTP requests and a 250 ms delay.
- Stops Batch on rate limiting, repeated session failures, cancellation, unload, or a Scope violation.
- Creates a redacted Burp Site Map Audit Issue only after **Confirm & report** is pressed.
- Exports metadata by default, with optional bounded and redacted evidence snippets. Raw HTTP export is intentionally unavailable.

Candidates and automated comparisons are review leads. Always confirm ownership, authorization rules, and real impact manually.

## Requirements and build

- A current Burp Suite Community or Professional release compatible with Montoya API 2026.4.
- JDK 17 or newer.

Linux or macOS:

```bash
./gradlew clean check jar
```

Windows:

```powershell
.\gradlew.bat clean check jar
```

The loadable extension is:

```text
build/libs/idor-bola-assistant-3.1.0.jar
```

`check` runs the test suite and enforces at least 80% line coverage for the non-UI core. GitHub Actions builds on Linux, macOS, and Windows and uploads the Linux JAR.

## Install

1. Open **Extensions > Installed** in Burp Suite.
2. Click **Add**, choose **Java**, and select `idor-bola-assistant-3.1.0.jar`.
3. Add only authorized targets to **Target > Scope**.
4. Open the **IDOR Assistant** suite tab.

## Recommended workflow

1. Proxy normal traffic from dedicated test accounts and roles. Discovery populates **Dashboard** without sending traffic.
2. Review **Suppressed** when needed. Restore a useful low-evidence reference, or use **Mark false positive** on a Dashboard item to create a narrow local rule.
3. Right-click a trusted authenticated request and select **IDOR Assistant > Capture as new identity profile**. Name the profile and add a role or tenant label.
4. Repeat for each test identity. The extension associates existing and future observations when their captured authentication matches a profile.
5. Select candidates in **Dashboard**, then choose the owner and target identities in **Test Matrix**.
6. Use **Compare one** for a single request, or **Run selected as Batch** for selected `GET/HEAD` candidates. Batch uses only object IDs already observed in Proxy traffic.
7. Review the original, owner-control, and cross-identity messages under **Evidence**.
8. Set the workflow status. Use **Confirm & report** only after manual validation; the Site Map issue contains redacted evidence.
9. Export HTML, JSON, or CSV metadata. Enable redacted snippets only when the report genuinely needs them.

## Profiles and session values

Profiles can contain selected authentication headers and detected CSRF/XSRF parameters. Applying a profile removes known authentication material from the source request, adds the selected profile headers, and updates matching session parameters by location.

Profiles are memory-only by default. If persistence is enabled, authentication material is stored inside the Burp project and is not encrypted by this extension. v2 Profile A/B data is migrated once when legacy persistence was enabled.

## Detection and comparison boundaries

- Request and response analysis is size- and depth-bounded. XML parsing disables DTD and external entities.
- Query values and raw reference values are masked in tables and excluded from reports.
- Authentication-context headers and cookies are excluded from object candidates. Weak generic references are suppressed until they have sufficient independent evidence.
- Scoped false-positive and allow rules contain only host, endpoint template, method, reference name/location/path, reason, and timestamp.
- Similar successful responses are not considered suspicious unless object-identity evidence is present.
- Login pages, redirects, WAF responses, rate limits, and CSRF/session failures remain inconclusive.
- An unstable owner baseline reduces the result to inconclusive.
- Mutation methods are excluded from Batch. A single mutation comparison sends only the cross-identity request after a warning; it does not repeat the owner mutation.
- The extension never registers an automatic Audit Check and never creates a Site Map issue without manual confirmation.

## الاستخدام السريع بالعربية

1. ابنِ الإضافة باستخدام `./gradlew clean check jar` وحمّل `build/libs/idor-bola-assistant-3.1.0.jar` كإضافة Java.
2. أضف الهدف المصرح به إلى **Target Scope**.
3. مرّر ترافيك حسابات الاختبار عبر Proxy؛ الاكتشاف السلبي لا يرسل أي طلبات.
4. اضغط بالزر الأيمن على Request موثوق واختر **Capture as new identity profile**، ثم اكتب اسم الحساب والدور أو الـtenant.
5. حدد Candidates والحساب المالك والحسابات الأخرى من **Test Matrix**. الـBatch يعمل فقط مع `GET/HEAD` وبحد افتراضي 20 طلبًا.
6. الإضافة تستخدم IDs شوهدت بالفعل فقط، ولا تخمّن أو تعمل enumeration.
7. راجع الأدلة يدويًا، ثم استخدم **Confirm & report** إذا تأكدت من النتيجة.
8. بيانات المصادقة لا تُحفظ افتراضيًا، والتقارير تحذفها وتحجب query values وObject IDs.
9. راجع تبويب **Suppressed** للحالات ضعيفة الأدلة، واستخدم **Mark false positive** لإنشاء قاعدة محلية محددة النطاق وقابلة للحذف.

## License

MIT. See [LICENSE](LICENSE). Runtime dependency notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
