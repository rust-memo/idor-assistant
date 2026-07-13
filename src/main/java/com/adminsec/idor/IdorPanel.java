package com.adminsec.idor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.adminsec.idor.model.Candidate;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.nio.file.Path;
import java.util.*;
import java.util.List;

public final class IdorPanel extends JPanel {
    private final MontoyaApi api;
    private final CandidateRepository repository;
    private final ProjectStore store;
    private final ComparisonService comparison;
    private final DetectionEngine detectionEngine;
    private IdentityProfile profileA;
    private IdentityProfile profileB;
    private boolean persistProfiles;
    private final CandidateModel model = new CandidateModel();
    private final JTable table = new JTable(model);
    private final JTextField filter = new JTextField(18);
    private final JComboBox<String> priority = new JComboBox<>(new String[]{"All priorities", "High", "Medium", "Low"});
    private final JComboBox<String> owner = new JComboBox<>(new String[]{"Owner: Profile A", "Owner: Profile B"});
    private final JComboBox<String> workflow = new JComboBox<>(new String[]{"New", "Reviewed", "Confirmed", "False positive", "Retest"});
    private final JLabel profiles = new JLabel();
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor originalEditor;
    private final HttpResponseEditor controlEditor;
    private final HttpResponseEditor crossEditor;

    public IdorPanel(MontoyaApi api, CandidateRepository repository, ProjectStore store, ComparisonService comparison, DetectionEngine detectionEngine) {
        super(new BorderLayout());
        this.api = api; this.repository = repository; this.store = store; this.comparison = comparison; this.detectionEngine = detectionEngine;
        this.persistProfiles = Boolean.parseBoolean(store.loadSetting("persistProfiles"));
        if (!persistProfiles) { store.clearProfile("A"); store.clearProfile("B"); }
        this.profileA = persistProfiles ? store.loadProfile("A") : emptyProfile("A");
        this.profileB = persistProfiles ? store.loadProfile("B") : emptyProfile("B");
        requestEditor = api.userInterface().createHttpRequestEditor();
        originalEditor = api.userInterface().createHttpResponseEditor();
        controlEditor = api.userInterface().createHttpResponseEditor();
        crossEditor = api.userInterface().createHttpResponseEditor();
        build();
        repository.addListener(this::refresh);
        refreshProfiles();
    }

    private void build() {
        JPanel top = new JPanel(); top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        JPanel primaryActions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        primaryActions.add(new JLabel("Filter:")); primaryActions.add(filter); primaryActions.add(priority); primaryActions.add(owner);
        primaryActions.add(button("Compare accounts", this::compareSelected));
        primaryActions.add(button("Test anonymous", this::compareAnonymous)); primaryActions.add(button("Cancel", comparison::cancel));
        JPanel secondaryActions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        secondaryActions.add(workflow); secondaryActions.add(button("Set status", this::setReviewStatus));
        secondaryActions.add(button("Repeater", this::sendRepeater)); secondaryActions.add(button("Comparer", this::sendComparer));
        secondaryActions.add(button("Export report", this::exportReport)); secondaryActions.add(button("Rules", this::editRules));
        secondaryActions.add(button("Profiles", this::manageProfiles)); secondaryActions.add(button("Clear auth", this::clearProfiles));
        secondaryActions.add(profiles); top.add(primaryActions); top.add(secondaryActions);
        add(top, BorderLayout.NORTH);

        table.setAutoCreateRowSorter(true); table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {55, 70, 65, 390, 220, 240, 110, 140, 260};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showSelected(); });
        JTabbedPane responses = new JTabbedPane();
        responses.addTab("Original response", originalEditor.uiComponent());
        responses.addTab("Owner control", controlEditor.uiComponent());
        responses.addTab("Other account", crossEditor.uiComponent());
        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responses);
        editors.setResizeWeight(.5);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), editors);
        split.setResizeWeight(.55); add(split, BorderLayout.CENTER);
        filter.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refresh(); } public void removeUpdate(DocumentEvent e) { refresh(); }
            public void changedUpdate(DocumentEvent e) { refresh(); }
        });
        priority.addActionListener(e -> refresh());
    }

    private JButton button(String label, Runnable action) {
        JButton button = new JButton(label); button.addActionListener(e -> action.run()); return button;
    }

    public void capture(String name, HttpRequestResponse message) {
        String displayName = store.loadSetting("profileName" + name);
        if (displayName.isBlank()) displayName = "Profile " + name;
        IdentityProfile found = IdentityProfile.capture(displayName, message.request());
        if (found.headers().isEmpty()) { JOptionPane.showMessageDialog(this, "No Cookie, Authorization, API key, or identity headers were found.", "Profile not captured", JOptionPane.WARNING_MESSAGE); return; }
        JList<String> choices = new JList<>(found.headers().keySet().toArray(String[]::new));
        choices.setSelectionInterval(0, choices.getModel().getSize() - 1);
        if (JOptionPane.showConfirmDialog(this, new JScrollPane(choices), "Select authentication headers for " + displayName,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return;
        Map<String, String> selected = new LinkedHashMap<>();
        for (String header : choices.getSelectedValuesList()) selected.put(header, found.headers().get(header));
        IdentityProfile captured = IdentityProfile.fromHeaders(displayName, selected);
        if (captured.headers().isEmpty()) { JOptionPane.showMessageDialog(this, "No Cookie, Authorization, API key, or identity headers were found.", "Profile not captured", JOptionPane.WARNING_MESSAGE); return; }
        if (persistProfiles) store.saveProfile(name, captured);
        if (name.equals("A")) profileA = captured; else profileB = captured;
        refreshProfiles();
    }

    private void refreshProfiles() { profiles.setText(" A: " + profileA.display() + " | B: " + profileB.display()); }
    private Candidate selected() { int view = table.getSelectedRow(); return view < 0 ? null : model.at(table.convertRowIndexToModel(view)); }
    private void showSelected() {
        Candidate c = selected(); if (c == null) return;
        requestEditor.setRequest(c.message().request());
        if (c.message().hasResponse()) originalEditor.setResponse(c.message().response());
        if (c.control() != null && c.control().hasResponse()) controlEditor.setResponse(c.control().response());
        if (c.cross() != null && c.cross().hasResponse()) crossEditor.setResponse(c.cross().response());
    }

    private void compareSelected() {
        Candidate c = selected(); if (c == null) return;
        String method = c.message().request().method();
        if (!Set.of("GET", "HEAD").contains(method)) {
            String warning = "This will send one " + method + " request as the other account and may modify data.\nHost: " + c.message().request().httpService().host() + "\nPath: " + c.message().request().pathWithoutQuery();
            if (JOptionPane.showConfirmDialog(this, warning, "Confirm state-changing request", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) return;
        }
        boolean aOwner = owner.getSelectedIndex() == 0;
        comparison.compare(c, aOwner ? profileA : profileB, aOwner ? profileB : profileA,
                done -> SwingUtilities.invokeLater(() -> { store.saveComparison(done.key(), done.comparisonStatus(), done.comparisonDetail()); repository.changed(); showSelected(); }),
                error -> SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, error, "Comparison failed", JOptionPane.ERROR_MESSAGE)));
    }

    private void compareAnonymous() {
        Candidate c = selected(); if (c == null) return;
        if (!confirmMutation(c, "anonymous")) return;
        boolean aOwner = owner.getSelectedIndex() == 0;
        comparison.compareAnonymous(c, aOwner ? profileA : profileB,
                done -> SwingUtilities.invokeLater(() -> { store.saveComparison(done.key(), done.comparisonStatus(), done.comparisonDetail()); repository.changed(); showSelected(); }),
                error -> SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, error, "Anonymous test failed", JOptionPane.ERROR_MESSAGE)));
    }

    private boolean confirmMutation(Candidate c, String target) {
        String method = c.message().request().method();
        if (Set.of("GET", "HEAD").contains(method)) return true;
        String warning = "This will send one " + method + " request as " + target + " and may modify data.\nHost: "
                + c.message().request().httpService().host() + "\nPath: " + c.message().request().pathWithoutQuery();
        return JOptionPane.showConfirmDialog(this, warning, "Confirm state-changing request",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION;
    }

    private void setReviewStatus() { Candidate c = selected(); if (c != null) { String status = (String) workflow.getSelectedItem(); c.reviewStatus(status); store.saveReviewStatus(c.key(), status); repository.changed(); } }
    private void sendRepeater() { Candidate c = selected(); if (c != null) api.repeater().sendToRepeater(c.message().request(), "IDOR candidate"); }
    private void sendComparer() {
        Candidate c = selected(); if (c == null) return;
        if (c.control() != null && c.cross() != null && c.control().hasResponse() && c.cross().hasResponse())
            api.comparer().sendToComparer(c.control().response().toByteArray(), c.cross().response().toByteArray());
        else JOptionPane.showMessageDialog(this, "Run an account comparison first.");
    }
    private void exportReport() {
        JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(new java.io.File("idor-candidates.html"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try { new ReportExporter().export(chooser.getSelectedFile().toPath(), model.rows); }
        catch (Exception e) { JOptionPane.showMessageDialog(this, e.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE); }
    }
    private void editRules() {
        JTextField allow = new JTextField(store.loadSetting("allowNames"), 42);
        JTextField deny = new JTextField(store.loadSetting("denyNames"), 42);
        JTextField paths = new JTextField(store.loadSetting("denyPaths"), 42);
        JTextField volatileFields = new JTextField(store.loadSetting("volatileFields"), 42);
        JTextField candidateLimit = new JTextField(settingOrDefault("candidateLimit", "5000"), 12);
        JTextField historyLimit = new JTextField(settingOrDefault("historyLimit", "10000"), 12);
        JTextField requestLimit = new JTextField(settingOrDefault("requestBodyLimit", "1048576"), 12);
        JTextField responseLimit = new JTextField(settingOrDefault("responseBodyLimit", "2097152"), 12);
        JPanel form = new JPanel(new GridLayout(0, 1));
        form.add(new JLabel("Additional identifier names (comma-separated):")); form.add(allow);
        form.add(new JLabel("Ignored parameter names (comma-separated):")); form.add(deny);
        form.add(new JLabel("Ignored path fragments (comma-separated):")); form.add(paths);
        form.add(new JLabel("Volatile JSON response fields (comma-separated):")); form.add(volatileFields);
        form.add(new JLabel("Candidate/history limits:")); form.add(pair(candidateLimit, historyLimit));
        form.add(new JLabel("Request/response body analysis byte limits:")); form.add(pair(requestLimit, responseLimit));
        if (JOptionPane.showConfirmDialog(this, form, "Detection rules", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        store.saveSetting("allowNames", allow.getText()); store.saveSetting("denyNames", deny.getText()); store.saveSetting("denyPaths", paths.getText());
        store.saveSetting("volatileFields", volatileFields.getText()); comparison.configureVolatileFields(splitRules(volatileFields.getText()));
        store.saveSetting("candidateLimit", candidateLimit.getText()); store.saveSetting("historyLimit", historyLimit.getText());
        store.saveSetting("requestBodyLimit", requestLimit.getText()); store.saveSetting("responseBodyLimit", responseLimit.getText());
        applyLimits(candidateLimit.getText(), requestLimit.getText(), responseLimit.getText());
        applyRules(allow.getText(), deny.getText(), paths.getText());
    }
    private void manageProfiles() {
        JTextField nameA = new JTextField(store.loadSetting("profileNameA").isBlank() ? profileA.name() : store.loadSetting("profileNameA"), 28);
        JTextField nameB = new JTextField(store.loadSetting("profileNameB").isBlank() ? profileB.name() : store.loadSetting("profileNameB"), 28);
        JCheckBox persist = new JCheckBox("Persist authentication in the Burp project", persistProfiles);
        JPanel form = new JPanel(new GridLayout(0, 1));
        form.add(new JLabel("Profile A display name:")); form.add(nameA);
        form.add(new JLabel("Profile B display name:")); form.add(nameB); form.add(persist);
        int choice = JOptionPane.showConfirmDialog(this, form, "Identity profiles", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) return;
        store.saveSetting("profileNameA", nameA.getText().trim()); store.saveSetting("profileNameB", nameB.getText().trim());
        persistProfiles = persist.isSelected(); store.saveSetting("persistProfiles", Boolean.toString(persistProfiles));
        profileA = IdentityProfile.fromHeaders(nameA.getText().trim().isBlank() ? "Profile A" : nameA.getText().trim(), profileA.headers());
        profileB = IdentityProfile.fromHeaders(nameB.getText().trim().isBlank() ? "Profile B" : nameB.getText().trim(), profileB.headers());
        if (persistProfiles) { store.saveProfile("A", profileA); store.saveProfile("B", profileB); }
        else { store.clearProfile("A"); store.clearProfile("B"); }
        refreshProfiles();
    }

    private IdentityProfile emptyProfile(String slot) {
        String configured = store.loadSetting("profileName" + slot);
        return IdentityProfile.fromHeaders(configured.isBlank() ? "Profile " + slot : configured, Map.of());
    }
    private void clearProfiles() {
        if (JOptionPane.showConfirmDialog(this, "Clear both authentication profiles from memory and project storage?",
                "Clear authentication", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) return;
        store.clearProfile("A"); store.clearProfile("B"); profileA = emptyProfile("A"); profileB = emptyProfile("B"); refreshProfiles();
    }
    public void applySavedRules() { applyRules(store.loadSetting("allowNames"), store.loadSetting("denyNames"), store.loadSetting("denyPaths"));
        comparison.configureVolatileFields(splitRules(store.loadSetting("volatileFields")));
        applyLimits(settingOrDefault("candidateLimit", "5000"), settingOrDefault("requestBodyLimit", "1048576"), settingOrDefault("responseBodyLimit", "2097152")); }
    private void applyRules(String allow, String deny, String paths) {
        detectionEngine.configure(splitRules(allow), splitRules(deny), splitRules(paths));
    }
    private List<String> splitRules(String text) { return Arrays.stream(text.split(",")).map(String::trim).filter(s -> !s.isBlank()).toList(); }
    private JPanel pair(JTextField left, JTextField right) { JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT)); row.add(left); row.add(right); return row; }
    private String settingOrDefault(String key, String fallback) { String value = store.loadSetting(key); return value.isBlank() ? fallback : value; }
    private void applyLimits(String candidates, String request, String response) {
        repository.setMaxCandidates(parseInt(candidates, 5000));
        detectionEngine.configureLimits(parseInt(request, 1_048_576), parseInt(response, 2_097_152));
    }
    private int parseInt(String value, int fallback) { try { return Integer.parseInt(value.trim()); } catch (Exception ignored) { return fallback; } }
    private void refresh() {
        String text = filter.getText().toLowerCase(Locale.ROOT); String wanted = (String) priority.getSelectedItem();
        List<Candidate> visible = repository.all().stream().filter(c -> wanted.startsWith("All") || c.assessment().priority().equals(wanted))
                .filter(c -> text.isBlank() || c.message().request().url().toLowerCase(Locale.ROOT).contains(text) || c.assessment().endpointTemplate().toLowerCase(Locale.ROOT).contains(text) || c.comparisonStatus().toLowerCase(Locale.ROOT).contains(text)).toList();
        model.setRows(visible);
    }

    private static final class CandidateModel extends AbstractTableModel {
        private final String[] columns = {"Score", "Priority", "Method", "URL", "Endpoint template", "References", "Review", "Comparison", "Detail"};
        private List<Candidate> rows = List.of();
        void setRows(List<Candidate> value) { rows = value; fireTableDataChanged(); }
        Candidate at(int row) { return rows.get(row); }
        public int getRowCount() { return rows.size(); } public int getColumnCount() { return columns.length; }
        public String getColumnName(int col) { return columns[col]; }
        public Class<?> getColumnClass(int col) { return col == 0 ? Integer.class : String.class; }
        public Object getValueAt(int row, int col) {
            Candidate c = rows.get(row); String refs = c.assessment().references().stream().limit(4).map(r -> r.name() + "=" + r.value()).reduce((a,b) -> a + "; " + b).orElse("");
            return switch (col) { case 0 -> c.assessment().score(); case 1 -> c.assessment().priority(); case 2 -> c.message().request().method();
                case 3 -> c.message().request().url(); case 4 -> c.assessment().endpointTemplate(); case 5 -> refs;
                case 6 -> c.reviewStatus(); case 7 -> c.comparisonStatus(); default -> c.comparisonDetail(); };
        }
    }
}
