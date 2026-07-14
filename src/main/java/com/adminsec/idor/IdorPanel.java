package com.adminsec.idor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.adminsec.idor.model.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/** v3 access-control workbench. Active traffic is delegated to ComparisonOrchestrator only. */
public final class IdorPanel extends JPanel {
    private final MontoyaApi api;
    private final CandidateCatalog catalog;
    private final ProjectStore store;
    private final ProfileManager profiles;
    private final ComparisonOrchestrator orchestrator;
    private final DetectionEngine detectionEngine;
    private final IssueReporter issueReporter;
    private final RedactionService redaction = new RedactionService();

    private final CandidateModel candidateModel = new CandidateModel();
    private final JTable candidateTable = new JTable(candidateModel);
    private final ProfileModel profileModel = new ProfileModel();
    private final JTable profileTable = new JTable(profileModel);
    private final JTextField filter = new JTextField(24);
    private final JComboBox<String> priority = new JComboBox<>(new String[]{"All priorities", "High", "Medium", "Low"});
    private final JComboBox<String> workflow = new JComboBox<>(new String[]{"New", "Reviewed", "Confirmed", "False positive", "Retest"});
    private final DefaultComboBoxModel<IdentityProfile> ownerProfiles = new DefaultComboBoxModel<>();
    private final DefaultComboBoxModel<IdentityProfile> targetProfiles = new DefaultComboBoxModel<>();
    private final JComboBox<IdentityProfile> owner = new JComboBox<>(ownerProfiles);
    private final JComboBox<IdentityProfile> target = new JComboBox<>(targetProfiles);
    private final DefaultListModel<IdentityProfile> matrixProfileModel = new DefaultListModel<>();
    private final JList<IdentityProfile> matrixTargets = new JList<>(matrixProfileModel);
    private final JCheckBox includeAnonymous = new JCheckBox("Include anonymous");
    private final JCheckBox persistProfiles = new JCheckBox("Persist profiles in this Burp project");
    private final JLabel runStatus = new JLabel("Idle");
    private final JProgressBar progress = new JProgressBar();
    private final JTextArea runLog = new JTextArea(8, 80);
    private final JTabbedPane workspace = new JTabbedPane();
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor originalEditor;
    private final HttpResponseEditor controlEditor;
    private final HttpResponseEditor crossEditor;

    private final JTextField allowNames;
    private final JTextField denyNames;
    private final JTextField denyPaths;
    private final JTextField volatileFields;
    private final JSpinner candidateLimit;
    private final JSpinner historyLimit;
    private final JSpinner requestLimit;
    private final JSpinner responseLimit;
    private final JSpinner requestBudget;
    private final JSpinner requestDelay;

    public IdorPanel(MontoyaApi api, CandidateCatalog catalog, ProjectStore store,
                     ProfileManager profiles, ComparisonOrchestrator orchestrator,
                     DetectionEngine detectionEngine) {
        super(new BorderLayout());
        this.api = api; this.catalog = catalog; this.store = store; this.profiles = profiles;
        this.orchestrator = orchestrator; this.detectionEngine = detectionEngine;
        this.issueReporter = new IssueReporter(api, redaction);
        requestEditor = api.userInterface().createHttpRequestEditor();
        originalEditor = api.userInterface().createHttpResponseEditor();
        controlEditor = api.userInterface().createHttpResponseEditor();
        crossEditor = api.userInterface().createHttpResponseEditor();
        allowNames = new JTextField(store.loadSetting("allowNames"), 42);
        denyNames = new JTextField(store.loadSetting("denyNames"), 42);
        denyPaths = new JTextField(store.loadSetting("denyPaths"), 42);
        volatileFields = new JTextField(store.loadSetting("volatileFields"), 42);
        candidateLimit = spinner("candidateLimit", 5_000, 100, 50_000, 100);
        historyLimit = spinner("historyLimit", 10_000, 100, 100_000, 100);
        requestLimit = spinner("requestBodyLimit", 1_048_576, 16_384, 10_485_760, 16_384);
        responseLimit = spinner("responseBodyLimit", 2_097_152, 16_384, 20_971_520, 16_384);
        requestBudget = spinner("requestBudget", 20, 2, 100, 1);
        requestDelay = spinner("requestDelay", 250, 0, 5_000, 50);
        build();
        catalog.addListener(this::refreshCandidates);
        profiles.addListener(() -> SwingUtilities.invokeLater(this::refreshProfiles));
        refreshProfiles(); applySavedRules(); refreshCandidates();
    }

    private void build() {
        workspace.addTab("Dashboard", buildCandidates());
        workspace.addTab("Profiles", buildProfiles());
        workspace.addTab("Test Matrix", buildMatrix());
        workspace.addTab("Evidence", buildEvidence());
        workspace.addTab("Settings", buildSettings());
        add(workspace, BorderLayout.CENTER);
    }

    private JComponent buildCandidates() {
        JPanel root = new JPanel(new BorderLayout());
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(new JLabel("Filter:")); actions.add(filter); actions.add(priority); actions.add(workflow);
        actions.add(button("Set status", this::setReviewStatus)); actions.add(button("Compare selected", this::compareSelected));
        actions.add(button("Repeater", this::sendRepeater)); actions.add(button("Export", this::exportReport));
        actions.add(button("Confirm & report", this::reportIssue));
        root.add(actions, BorderLayout.NORTH);
        candidateTable.setAutoCreateRowSorter(true); candidateTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        candidateTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        int[] widths = {55, 70, 65, 330, 190, 85, 240, 110, 150, 280};
        for (int i = 0; i < widths.length; i++) candidateTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        candidateTable.getSelectionModel().addListSelectionListener(event -> { if (!event.getValueIsAdjusting()) showSelected(); });
        root.add(new JScrollPane(candidateTable), BorderLayout.CENTER);
        filter.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refreshCandidates(); }
            public void removeUpdate(DocumentEvent e) { refreshCandidates(); }
            public void changedUpdate(DocumentEvent e) { refreshCandidates(); }
        });
        priority.addActionListener(event -> refreshCandidates());
        return root;
    }

    private JComponent buildProfiles() {
        JPanel root = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Capture profiles from a selected Burp request using the context menu."));
        top.add(button("Remove selected", this::removeProfile));
        persistProfiles.setSelected(profiles.persistenceEnabled());
        persistProfiles.addActionListener(event -> changePersistence()); top.add(persistProfiles);
        root.add(top, BorderLayout.NORTH); root.add(new JScrollPane(profileTable), BorderLayout.CENTER);
        JTextArea help = new JTextArea("Secrets stay in memory by default. Session-bound CSRF/XSRF parameters are captured with the identity and are never shown in full.");
        help.setEditable(false); help.setLineWrap(true); help.setWrapStyleWord(true); root.add(help, BorderLayout.SOUTH);
        return root;
    }

    private JComponent buildMatrix() {
        JPanel root = new JPanel(new BorderLayout());
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        configureProfileRenderer(owner); configureProfileRenderer(target);
        controls.add(new JLabel("Owner:")); controls.add(owner); controls.add(new JLabel("Single target:")); controls.add(target);
        controls.add(button("Compare one", this::compareSelected)); controls.add(button("Run selected as Batch", this::runBatch));
        controls.add(button("Cancel", orchestrator::cancel)); controls.add(includeAnonymous);
        root.add(controls, BorderLayout.NORTH);
        matrixTargets.setVisibleRowCount(6); matrixTargets.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JPanel center = new JPanel(new BorderLayout());
        center.add(new JLabel("Batch target profiles (GET/HEAD only, observed IDs only):"), BorderLayout.NORTH);
        center.add(new JScrollPane(matrixTargets), BorderLayout.WEST);
        runLog.setEditable(false); runLog.setLineWrap(true); center.add(new JScrollPane(runLog), BorderLayout.CENTER);
        root.add(center, BorderLayout.CENTER);
        JPanel status = new JPanel(new BorderLayout()); status.add(runStatus, BorderLayout.WEST); status.add(progress, BorderLayout.CENTER);
        root.add(status, BorderLayout.SOUTH); return root;
    }

    private JComponent buildEvidence() {
        JTabbedPane responses = new JTabbedPane();
        responses.addTab("Original response", originalEditor.uiComponent());
        responses.addTab("Owner control", controlEditor.uiComponent());
        responses.addTab("Other identity", crossEditor.uiComponent());
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responses);
        split.setResizeWeight(.45); return split;
    }

    private JComponent buildSettings() {
        JPanel form = new JPanel(new GridBagLayout()); GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = 0; c.anchor = GridBagConstraints.WEST; c.insets = new Insets(4, 6, 4, 6);
        addSetting(form, c, "Additional identifier names", allowNames);
        addSetting(form, c, "Ignored parameter names", denyNames);
        addSetting(form, c, "Ignored path fragments", denyPaths);
        addSetting(form, c, "Volatile response fields", volatileFields);
        addSetting(form, c, "Candidate limit", candidateLimit); addSetting(form, c, "History scan limit (next load)", historyLimit);
        addSetting(form, c, "Request body byte limit", requestLimit); addSetting(form, c, "Response body byte limit", responseLimit);
        addSetting(form, c, "Batch request budget", requestBudget); addSetting(form, c, "Delay between requests (ms)", requestDelay);
        c.gridx = 1; c.gridy++; form.add(button("Save settings", this::saveSettings), c);
        JPanel root = new JPanel(new BorderLayout()); root.add(form, BorderLayout.NORTH);
        return root;
    }

    private void addSetting(JPanel form, GridBagConstraints c, String name, Component field) {
        c.gridx = 0; form.add(new JLabel(name + ":"), c); c.gridx = 1; form.add(field, c); c.gridy++;
    }
    private JSpinner spinner(String key, int fallback, int min, int max, int step) {
        return new JSpinner(new SpinnerNumberModel(parseInt(settingOrDefault(key, Integer.toString(fallback)), fallback), min, max, step));
    }
    private JButton button(String label, Runnable action) { JButton value = new JButton(label); value.addActionListener(e -> action.run()); return value; }
    private void configureProfileRenderer(JComboBox<IdentityProfile> combo) {
        combo.setRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                return super.getListCellRendererComponent(list, value instanceof IdentityProfile p ? p.display() : "No profile", index, selected, focus);
            }
        });
    }

    public void capture(HttpRequestResponse message) { capture("", message); }

    /** Compatibility entry point; slot is used only as a suggested name. */
    public void capture(String slot, HttpRequestResponse message) {
        IdentityProfile found = IdentityProfile.capture(slot.isBlank() ? "Profile" : "Profile " + slot, message.request());
        if (found.headers().isEmpty()) {
            JOptionPane.showMessageDialog(this, "No Cookie, Authorization, API key, CSRF, or identity headers were found.",
                    "Profile not captured", JOptionPane.WARNING_MESSAGE); return;
        }
        JTextField name = new JTextField(found.name(), 28); JTextField role = new JTextField(18);
        JList<String> headers = new JList<>(found.headers().keySet().toArray(String[]::new));
        headers.setSelectionInterval(0, headers.getModel().getSize() - 1);
        JPanel form = new JPanel(new GridLayout(0, 1)); form.add(new JLabel("Profile name:")); form.add(name);
        form.add(new JLabel("Role/tenant label:")); form.add(role); form.add(new JLabel("Authentication headers to capture:"));
        form.add(new JScrollPane(headers)); form.add(new JLabel("Session substitutions detected: " + found.substitutions().size()));
        if (JOptionPane.showConfirmDialog(this, form, "Capture identity profile", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return;
        Map<String, String> selected = new LinkedHashMap<>();
        headers.getSelectedValuesList().forEach(header -> selected.put(header, found.headers().get(header)));
        if (selected.isEmpty()) { JOptionPane.showMessageDialog(this, "Select at least one authentication header."); return; }
        IdentityProfile captured = new IdentityProfile(found.id(), name.getText().trim(), role.getText().trim(), selected,
                found.substitutions(), IdentityProfile.fingerprint(selected, found.substitutions()));
        profiles.upsert(captured); catalog.assignOwner(captured);
    }

    private void refreshProfiles() {
        String ownerId = selectedProfile(owner).map(IdentityProfile::id).orElse("");
        String targetId = selectedProfile(target).map(IdentityProfile::id).orElse("");
        ownerProfiles.removeAllElements(); targetProfiles.removeAllElements(); matrixProfileModel.clear();
        for (IdentityProfile profile : profiles.all()) {
            ownerProfiles.addElement(profile); targetProfiles.addElement(profile); matrixProfileModel.addElement(profile);
        }
        selectProfile(owner, ownerId); selectProfile(target, targetId);
        if (matrixProfileModel.size() > 0) matrixTargets.setSelectionInterval(0, matrixProfileModel.size() - 1);
        profileModel.setRows(profiles.all());
    }

    private void changePersistence() {
        if (persistProfiles.isSelected()) {
            int choice = JOptionPane.showConfirmDialog(this,
                    "Authentication material will be stored inside the Burp project. The extension does not encrypt it. Continue?",
                    "Persist sensitive profiles", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.OK_OPTION) { persistProfiles.setSelected(false); return; }
        }
        profiles.persistenceEnabled(persistProfiles.isSelected());
    }

    private void removeProfile() {
        int row = profileTable.getSelectedRow(); if (row < 0) return;
        IdentityProfile profile = profileModel.at(profileTable.convertRowIndexToModel(row));
        if (JOptionPane.showConfirmDialog(this, "Remove " + profile.name() + " from memory and project storage?",
                "Remove profile", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) profiles.remove(profile.id());
    }

    private Candidate selectedCandidate() {
        int row = candidateTable.getSelectedRow(); return row < 0 ? null : candidateModel.at(candidateTable.convertRowIndexToModel(row));
    }
    private List<Candidate> selectedCandidates() {
        return Arrays.stream(candidateTable.getSelectedRows()).map(candidateTable::convertRowIndexToModel).mapToObj(candidateModel::at).toList();
    }
    private ObjectObservation observation(Candidate candidate, IdentityProfile ownerProfile) {
        List<ObjectObservation> rows = candidate.observations();
        if (ownerProfile != null) for (int i = rows.size() - 1; i >= 0; i--)
            if (ownerProfile.id().equals(rows.get(i).ownerProfileId())) return rows.get(i);
        return rows.isEmpty() ? null : rows.get(rows.size() - 1);
    }

    private void showSelected() {
        Candidate candidate = selectedCandidate(); if (candidate == null) return;
        requestEditor.setRequest(candidate.message().request());
        if (candidate.message().hasResponse()) originalEditor.setResponse(candidate.message().response());
        if (candidate.control() != null && candidate.control().hasResponse()) controlEditor.setResponse(candidate.control().response());
        if (candidate.cross() != null && candidate.cross().hasResponse()) crossEditor.setResponse(candidate.cross().response());
        candidate.observations().stream().map(ObjectObservation::ownerProfileId).filter(id -> !id.isBlank()).findFirst()
                .ifPresent(id -> selectProfile(owner, id));
    }

    private void compareSelected() {
        Candidate candidate = selectedCandidate(); IdentityProfile ownerProfile = (IdentityProfile) owner.getSelectedItem();
        IdentityProfile targetProfile = (IdentityProfile) target.getSelectedItem();
        if (candidate == null || ownerProfile == null) { message("Select a candidate and owner profile."); return; }
        boolean anonymous = includeAnonymous.isSelected();
        if (!anonymous && targetProfile == null) { message("Select a target profile."); return; }
        ObjectObservation sample = observation(candidate, ownerProfile); if (sample == null) return;
        if (!confirmMutation(sample.message(), anonymous ? "anonymous" : targetProfile.name())) return;
        runStatus.setText("Running one comparison..."); workspace.setSelectedIndex(2);
        orchestrator.compareSingle(candidate, sample, ownerProfile, targetProfile, anonymous,
                evidence -> SwingUtilities.invokeLater(() -> finish(candidate, evidence.status())),
                error -> SwingUtilities.invokeLater(() -> fail(error)));
    }

    private void runBatch() {
        List<Candidate> selected = selectedCandidates(); IdentityProfile ownerProfile = (IdentityProfile) owner.getSelectedItem();
        if (selected.isEmpty() || ownerProfile == null) { message("Select one or more candidates and an owner profile."); return; }
        List<IdentityProfile> targets = matrixTargets.getSelectedValuesList().stream()
                .filter(profile -> !profile.id().equals(ownerProfile.id())).toList();
        List<ComparisonOrchestrator.ComparisonCase> cases = new ArrayList<>();
        for (Candidate candidate : selected) {
            ObjectObservation sample = observation(candidate, ownerProfile); if (sample == null) continue;
            for (IdentityProfile targetProfile : targets)
                cases.add(new ComparisonOrchestrator.ComparisonCase(candidate, sample, ownerProfile, targetProfile, false));
            if (includeAnonymous.isSelected()) cases.add(new ComparisonOrchestrator.ComparisonCase(candidate, sample, ownerProfile, null, true));
        }
        if (cases.isEmpty()) { message("Select at least one different target profile or anonymous."); return; }
        runLog.setText(""); progress.setMaximum(cases.size()); progress.setValue(0); runStatus.setText("Batch running...");
        orchestrator.runBatch(cases, new ComparisonOrchestrator.Listener() {
            @Override public void onEvidence(ComparisonOrchestrator.ComparisonCase test, ComparisonEvidence evidence) {
                SwingUtilities.invokeLater(() -> { persist(test.candidate()); append(test.candidate().assessment().endpointTemplate() + " -> " + evidence.status()); });
            }
            @Override public void onProgress(int complete, int total, int requests) {
                SwingUtilities.invokeLater(() -> { progress.setValue(complete); runStatus.setText(complete + "/" + total + " cases; " + requests + " requests"); });
            }
            @Override public void onError(ComparisonOrchestrator.ComparisonCase test, String error) {
                SwingUtilities.invokeLater(() -> append("Skipped: " + error));
            }
            @Override public void onStopped(ComparisonOrchestrator.RunSummary summary) {
                SwingUtilities.invokeLater(() -> { runStatus.setText(summary.reason() + "; " + summary.requestsSent() + " requests"); catalog.changed(); });
            }
        });
    }

    private boolean confirmMutation(HttpRequestResponse message, String targetName) {
        String method = message.request().method().toUpperCase(Locale.ROOT);
        if (Set.of("GET", "HEAD").contains(method)) return true;
        String warning = "This sends one " + method + " request as " + targetName + " and may modify data.\nHost: "
                + message.request().httpService().host() + "\nPath: " + message.request().pathWithoutQuery();
        return JOptionPane.showConfirmDialog(this, warning, "Confirm state-changing request",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION;
    }

    private void finish(Candidate candidate, String status) { persist(candidate); runStatus.setText(status); catalog.changed(); showSelected(); }
    private void fail(String error) { runStatus.setText("Failed"); JOptionPane.showMessageDialog(this, error, "Comparison failed", JOptionPane.ERROR_MESSAGE); }
    private void persist(Candidate candidate) { store.saveComparison(candidate.key(), candidate.comparisonStatus(), candidate.comparisonDetail()); }
    private void append(String value) { runLog.append(value + "\n"); }
    private void message(String value) { JOptionPane.showMessageDialog(this, value); }

    private void setReviewStatus() {
        for (Candidate candidate : selectedCandidates()) {
            String status = (String) workflow.getSelectedItem(); candidate.reviewStatus(status); store.saveReviewStatus(candidate.key(), status);
        }
        catalog.changed();
    }
    private void sendRepeater() { Candidate candidate = selectedCandidate(); if (candidate != null) api.repeater().sendToRepeater(candidate.message().request(), "IDOR candidate"); }

    private void exportReport() {
        JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(new java.io.File("idor-candidates.html"));
        JCheckBox evidence = new JCheckBox("Include redacted evidence snippets (never raw HTTP)"); chooser.setAccessory(evidence);
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try { new ReportExporter().export(chooser.getSelectedFile().toPath(), candidateModel.rows, evidence.isSelected()); }
        catch (Exception error) { JOptionPane.showMessageDialog(this, error.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE); }
    }

    private void reportIssue() {
        Candidate candidate = selectedCandidate(); if (candidate == null) return;
        JComboBox<String> severity = new JComboBox<>(new String[]{"High", "Medium", "Low"});
        boolean sensitive = candidate.assessment().references().stream().anyMatch(ref -> "Sensitive".equals(ref.sensitivity()));
        severity.setSelectedItem(sensitive ? "High" : "Medium");
        JPanel form = new JPanel(new GridLayout(0, 1));
        form.add(new JLabel("Add a redacted Potential IDOR/BOLA issue to Burp Site Map?")); form.add(new JLabel("Severity:")); form.add(severity);
        if (JOptionPane.showConfirmDialog(this, form, "Confirm reviewed issue", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) return;
        try {
            issueReporter.report(candidate, switch ((String) severity.getSelectedItem()) {
                case "High" -> AuditIssueSeverity.HIGH; case "Low" -> AuditIssueSeverity.LOW; default -> AuditIssueSeverity.MEDIUM;
            });
            candidate.reviewStatus("Confirmed"); store.saveReviewStatus(candidate.key(), "Confirmed"); catalog.changed();
        } catch (Exception error) { JOptionPane.showMessageDialog(this, error.getMessage(), "Issue not created", JOptionPane.ERROR_MESSAGE); }
    }

    private void saveSettings() {
        store.saveSetting("allowNames", allowNames.getText()); store.saveSetting("denyNames", denyNames.getText());
        store.saveSetting("denyPaths", denyPaths.getText()); store.saveSetting("volatileFields", volatileFields.getText());
        saveNumber("candidateLimit", candidateLimit); saveNumber("historyLimit", historyLimit);
        saveNumber("requestBodyLimit", requestLimit); saveNumber("responseBodyLimit", responseLimit);
        saveNumber("requestBudget", requestBudget); saveNumber("requestDelay", requestDelay);
        applySavedRules(); message("Settings saved. The history limit applies on the next extension load.");
    }
    private void saveNumber(String key, JSpinner value) { store.saveSetting(key, value.getValue().toString()); }

    public void applySavedRules() {
        detectionEngine.configure(splitRules(allowNames.getText()), splitRules(denyNames.getText()), splitRules(denyPaths.getText()));
        detectionEngine.configureLimits((Integer) requestLimit.getValue(), (Integer) responseLimit.getValue());
        catalog.setMaxCandidates((Integer) candidateLimit.getValue());
        orchestrator.configureVolatileFields(splitRules(volatileFields.getText()));
        orchestrator.configureBatch((Integer) requestBudget.getValue(), ((Integer) requestDelay.getValue()).longValue());
    }

    private List<String> splitRules(String text) { return Arrays.stream(text.split(",")).map(String::trim).filter(value -> !value.isBlank()).toList(); }
    private String settingOrDefault(String key, String fallback) { String value = store.loadSetting(key); return value.isBlank() ? fallback : value; }
    private int parseInt(String value, int fallback) { try { return Integer.parseInt(value.trim()); } catch (Exception ignored) { return fallback; } }

    private void refreshCandidates() {
        String text = filter.getText().toLowerCase(Locale.ROOT); String wanted = (String) priority.getSelectedItem();
        List<Candidate> visible = catalog.all().stream()
                .filter(candidate -> wanted.startsWith("All") || candidate.assessment().priority().equals(wanted))
                .filter(candidate -> text.isBlank() || candidate.message().request().url().toLowerCase(Locale.ROOT).contains(text)
                        || candidate.assessment().endpointTemplate().toLowerCase(Locale.ROOT).contains(text)
                        || candidate.comparisonStatus().toLowerCase(Locale.ROOT).contains(text)).toList();
        candidateModel.setRows(visible);
    }

    private Optional<IdentityProfile> selectedProfile(JComboBox<IdentityProfile> combo) { return Optional.ofNullable((IdentityProfile) combo.getSelectedItem()); }
    private void selectProfile(JComboBox<IdentityProfile> combo, String id) {
        if (id == null || id.isBlank()) return;
        for (int i = 0; i < combo.getItemCount(); i++) if (id.equals(combo.getItemAt(i).id())) { combo.setSelectedIndex(i); return; }
    }

    private final class CandidateModel extends AbstractTableModel {
        private final String[] columns = {"Score", "Priority", "Method", "URL", "Endpoint", "Samples", "References", "Review", "Comparison", "Detail"};
        private List<Candidate> rows = List.of();
        void setRows(List<Candidate> value) { rows = value; fireTableDataChanged(); }
        Candidate at(int row) { return rows.get(row); }
        public int getRowCount() { return rows.size(); } public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Class<?> getColumnClass(int column) { return column == 0 || column == 5 ? Integer.class : String.class; }
        public Object getValueAt(int row, int column) {
            Candidate candidate = rows.get(row);
            String refs = candidate.assessment().references().stream().filter(ref -> "Request".equals(ref.source())).limit(4)
                    .map(ref -> ref.name() + "=#" + redaction.fingerprint(ref.value())).reduce((a, b) -> a + "; " + b).orElse("");
            return switch (column) {
                case 0 -> candidate.assessment().score(); case 1 -> candidate.assessment().priority();
                case 2 -> candidate.message().request().method(); case 3 -> displayUrl(candidate.message().request().url());
                case 4 -> candidate.assessment().endpointTemplate(); case 5 -> candidate.observations().size(); case 6 -> refs;
                case 7 -> candidate.reviewStatus(); case 8 -> candidate.comparisonStatus(); default -> candidate.comparisonDetail();
            };
        }
    }

    private String displayUrl(String url) {
        return url == null ? "" : url.replaceAll("([?&][^=&]+)=[^&]*", "$1=<redacted>");
    }

    private static final class ProfileModel extends AbstractTableModel {
        private final String[] columns = {"Name", "Role/Tenant", "Auth headers", "Session values", "Fingerprint"};
        private List<IdentityProfile> rows = List.of();
        void setRows(List<IdentityProfile> value) { rows = value; fireTableDataChanged(); }
        IdentityProfile at(int row) { return rows.get(row); }
        public int getRowCount() { return rows.size(); } public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Object getValueAt(int row, int column) {
            IdentityProfile profile = rows.get(row);
            return switch (column) { case 0 -> profile.name(); case 1 -> profile.role(); case 2 -> profile.headers().size();
                case 3 -> profile.substitutions().size(); default -> profile.fingerprint().substring(0, 12); };
        }
    }
}
