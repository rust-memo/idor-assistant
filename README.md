# IDOR/BOLA Assistant for Burp Suite

IDOR/BOLA Assistant is a Montoya-based Burp Suite extension that helps authorized testers find object-reference candidates, compare access between two test accounts, and document the result without claiming a vulnerability from passive evidence alone.

The passive analyzer never sends requests. Account and anonymous comparisons run only after a user action, and the extension blocks active comparisons outside Burp Target Scope.

## Features

- Reviews recent Proxy history and new Proxy responses for identifiers in URL, form, JSON, XML, multipart, headers, and paths.
- Scores and prioritizes candidates while keeping passive observations separate from confirmed findings.
- Captures selected authentication headers as Profile A and Profile B from Burp's context menu.
- Compares an owner control response with a cross-account response for `GET` and `HEAD` requests.
- Sends only the cross-account request for state-changing methods, after an explicit warning, to avoid repeating the owner-side action.
- Supports a separately confirmed anonymous-access comparison.
- Compares status codes, normalized bodies, JSON structure, sensitive fields, login responses, and selected volatile JSON fields.
- Sends collected evidence to Repeater or Comparer for manual investigation.
- Saves review states and comparison summaries in the Burp project.
- Exports metadata-only HTML, JSON, and CSV reports without authentication headers, query values, or message bodies.

Candidates are review leads, not proof of IDOR/BOLA. Confirm ownership, authorization rules, and actual server-side impact manually.

## Requirements

- A current Burp Suite Community or Professional release compatible with Montoya API 2026.4.
- JDK 17 or newer to build the extension.

## Build

The repository includes a Gradle wrapper, so a separate Gradle installation is not required.

Linux or macOS:

```bash
./gradlew clean test jar
```

Windows:

```powershell
.\gradlew.bat clean test jar
```

The loadable JAR is created at:

```text
build/libs/idor-bola-assistant-2.0.0.jar
```

Do not load a plain source archive into Burp. Build the project or download the JAR from a trusted GitHub release or workflow artifact.

GitHub Actions runs all tests and publishes the JAR as a directly downloadable workflow artifact. For public distribution, attach that tested file to a versioned GitHub Release instead of committing `build/`.

## Install in Burp Suite

1. Open **Extensions > Installed**.
2. Click **Add** and choose extension type **Java**.
3. Select `build/libs/idor-bola-assistant-2.0.0.jar`.
4. Check Burp's **Output** and **Errors** tabs, then open the new **IDOR Assistant** tab.
5. Add only authorized targets to **Target > Scope** before using comparisons.

## Suggested workflow

1. Proxy normal traffic for test accounts A and B. Passive discovery will populate the candidate list.
2. Right-click a trusted authenticated request for each account and choose **IDOR Assistant > Capture authentication as Profile A/B**.
3. Select only the authentication headers that should be copied. Profiles stay in memory unless project persistence is explicitly enabled under **Profiles**.
4. Select a candidate and set which profile owns the referenced object.
5. For a safe read request, click **Compare accounts**. For a mutation, read and accept the warning only when a cross-account request is safe and authorized.
6. Review the original, owner-control, and other-account responses. Use **Comparer** or **Repeater** when additional manual checks are needed.
7. Record a workflow status such as Reviewed, Confirmed, False positive, or Retest, then export a report.

## Safety and privacy

- Target Scope is a hard boundary for active comparisons.
- Passive analysis does not mutate identifiers, enumerate values, or send traffic.
- Authentication profiles are memory-only by default. Optional persistence stores them inside the Burp project and can be cleared from the extension.
- `POST`, `PUT`, `PATCH`, `DELETE`, and other non-read methods can change data. The extension asks for confirmation and sends at most the cross-account request during an account comparison.
- Reports intentionally exclude authentication material, HTTP bodies, and query values.
- Use dedicated test accounts and only test systems for which you have explicit authorization.

## Limitations

- Similar responses do not by themselves prove unauthorized access; applications often return generic or cached content.
- Different responses do not prove protection; resource state and account-specific presentation may legitimately differ.
- The extension does not guess object identifiers or automatically change a request's object reference.
- Binary and highly custom payloads may require manual analysis.

## الاستخدام السريع بالعربية

1. ابنِ الإضافة بالأمر `./gradlew clean test jar`، ثم حمّل `build/libs/idor-bola-assistant-2.0.0.jar` كإضافة **Java**.
2. أضف الهدف المصرح به إلى **Target Scope**.
3. مرّر ترافيك الحسابين التجريبيين A وB عبر Proxy.
4. اضغط بالزر الأيمن على طلب موثوق لكل حساب واختر **Capture authentication as Profile A/B**.
5. اختر المرشح وحدد الحساب المالك، ثم استخدم **Compare accounts**. طلبات التعديل تحتاج تأكيدًا وقد تغيّر البيانات.
6. راجع الردود يدويًا؛ نتيجة المقارنة إرشاد وليست إثباتًا تلقائيًا للثغرة.
7. بيانات المصادقة لا تُحفظ افتراضيًا، والتقارير لا تصدرها ولا تصدر محتوى الطلبات والردود.

## License

MIT. See [LICENSE](LICENSE). Runtime dependency notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
