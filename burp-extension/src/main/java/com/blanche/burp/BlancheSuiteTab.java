package com.blanche.burp;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

public final class BlancheSuiteTab {
    private static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 12);

    private final MontoyaApi api;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final BlancheSiteMapIntegrator siteMapIntegrator;
    private final BlancheHostRegistry registry = new BlancheHostRegistry();

    private final JPanel rootPanel = new JPanel(new BorderLayout());
    private final JTextArea hostArea = buildTextArea();
    private final JTextArea summaryArea = buildTextArea();
    private final JTextArea artifactsArea = buildTextArea();
    private final JTextArea storageArea = buildTextArea();
    private final JTextArea provenanceArea = buildTextArea();
    private final JTextArea trafficLedgerArea = buildTextArea();
    private final JTextArea pageRawArea = buildTextArea();
    private final JTextArea endpointArea = buildTextArea();
    private final JTextArea endpointRawArea = buildTextArea();
    private final JTextArea osintSeedArea = buildTextArea();
    private final JTextArea osintSeedRawArea = buildTextArea();
    private final JTextArea osintSummaryArea = buildTextArea();
    private final JTextArea osintFindingsArea = buildTextArea();
    private final JTextArea osintReportRawArea = buildTextArea();

    private final JLabel endpointLabel = new JLabel("Auto ingest endpoint pending.");
    private final JLabel statusLabel = new JLabel(
        "Load a BLANCHE export JSON file or send one automatically from Chromium."
    );
    private final JLabel osintStatusLabel = new JLabel("OSINT orchestration pending.");

    private Runnable runOsintHandler = () -> {};

    private JTree hostTree;
    private DefaultTreeModel treeModel;
    private JTabbedPane detailTabs;

    public BlancheSuiteTab(MontoyaApi api) {
        this.api = api;
        this.siteMapIntegrator = new BlancheSiteMapIntegrator(api);
        rootPanel.setPreferredSize(new Dimension(1080, 760));
        rootPanel.add(buildToolbar(), BorderLayout.NORTH);
        rootPanel.add(buildSplitPane(), BorderLayout.CENTER);
    }

    public JPanel getComponent() {
        return rootPanel;
    }

    public void setRunOsintHandler(Runnable handler) {
        this.runOsintHandler = handler == null ? () -> {} : handler;
    }

    public void setAutoIngestEndpoint(String endpoint) {
        SwingUtilities.invokeLater(() -> {
            endpointLabel.setText("Auto ingest: " + endpoint);
            endpointLabel.setToolTipText(endpoint);
        });
    }

    public void setAutoIngestStatus(String message) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(message));
    }

    public void setOsintStatus(String message) {
        SwingUtilities.invokeLater(() -> osintStatusLabel.setText(message));
    }

    public IngestionResult ingestJson(String rawJson, String sourceLabel) throws IOException {
        return ingestBrowserExport(rawJson, sourceLabel);
    }

    public IngestionResult ingestBrowserExport(String rawJson, String sourceLabel) throws IOException {
        JsonNode root = objectMapper.readTree(rawJson);
        String prettyJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        BlancheSiteMapIntegrator.IntegrationResult siteMapResult = integrateIntoSiteMap(root);
        BlancheHostRegistry.PageIngestSummary pageSummary = registry.recordExport(root, prettyJson, sourceLabel);

        IngestionResult result = new IngestionResult(
            sourceLabel,
            root.at("/page/url").asText(""),
            root.at("/summary/artifactCount").asInt(root.path("artifacts").size()),
            siteMapResult.chromiumOnlyArtifactCount(),
            siteMapResult.highlighted(),
            siteMapResult.statusMessage()
        );

        SwingUtilities.invokeLater(() -> {
            rebuildTree(pageSummary.hostname(), NodeKind.PAGE, String.valueOf(pageSummary.pageId()));
            statusLabel.setText(buildStatusLine(result));
        });

        return result;
    }

    public OsintSeedResult ingestOsintSeed(String rawJson, String sourceLabel) throws IOException {
        JsonNode root = objectMapper.readTree(rawJson);
        String prettyJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        BlancheHostRegistry.OsintSeedIngestSummary seedSummary = registry.recordOsintSeed(root, prettyJson, sourceLabel);

        OsintSeedResult result = new OsintSeedResult(
            sourceLabel,
            seedSummary.primaryHostname(),
            seedSummary.relatedHostCount()
        );

        SwingUtilities.invokeLater(() -> {
            rebuildTree(seedSummary.hostname(), NodeKind.OSINT_SEED, null);
            osintStatusLabel.setText(
                "Loaded OSINT seed for "
                    + (result.primaryHostname().isBlank() ? "(unknown host)" : result.primaryHostname())
                    + " via "
                    + result.sourceLabel()
                    + "."
            );
        });

        return result;
    }

    public OsintReportResult ingestOsintReport(String rawJson, String sourceLabel) throws IOException {
        JsonNode root = objectMapper.readTree(rawJson);
        String prettyJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        BlancheHostRegistry.OsintReportIngestSummary reportSummary = registry.recordOsintReport(
            root,
            prettyJson,
            sourceLabel
        );

        OsintReportResult result = new OsintReportResult(
            sourceLabel,
            reportSummary.primaryHostname(),
            reportSummary.findingCount()
        );

        SwingUtilities.invokeLater(() -> {
            rebuildTree(reportSummary.hostname(), NodeKind.OSINT_REPORT, null);
            osintStatusLabel.setText(
                "Loaded OSINT report for "
                    + (result.primaryHostname().isBlank() ? "(unknown host)" : result.primaryHostname())
                    + " via "
                    + result.sourceLabel()
                    + "."
            );
        });

        return result;
    }

    private JToolBar buildToolbar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);

        JButton loadButton = new JButton("Load JSON");
        loadButton.addActionListener(event -> loadExportFromDisk());

        JButton runOsintButton = new JButton("Run OSINT");
        runOsintButton.addActionListener(event -> runOsintHandler.run());

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(event -> clearViews());

        toolBar.add(loadButton);
        toolBar.add(runOsintButton);
        toolBar.add(clearButton);
        toolBar.addSeparator();
        toolBar.add(endpointLabel);
        toolBar.addSeparator();
        toolBar.add(statusLabel);
        toolBar.addSeparator();
        toolBar.add(osintStatusLabel);
        return toolBar;
    }

    private JSplitPane buildSplitPane() {
        BlancheNode initialRoot = new BlancheNode(NodeKind.ROOT, null, null, "BLANCHE Hosts");
        treeModel = new DefaultTreeModel(initialRoot);
        hostTree = new JTree(treeModel);
        hostTree.setRootVisible(false);
        hostTree.setShowsRootHandles(true);
        hostTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        hostTree.addTreeSelectionListener(event -> {
            Object component = hostTree.getLastSelectedPathComponent();
            if (component instanceof BlancheNode node) {
                renderNode(node);
            }
        });

        detailTabs = new JTabbedPane();
        detailTabs.addTab("Details", wrap(hostArea));
        hostArea.setText(
            "Select a host, page, Chromium-only endpoint, or OSINT node from the tree on the left.\n"
                + "Every ingested browser export and OSINT payload is paired here by hostname and endpoint."
        );

        JScrollPane treeScroll = new JScrollPane(hostTree);
        treeScroll.setPreferredSize(new Dimension(340, 700));

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, detailTabs);
        splitPane.setResizeWeight(0.28);
        splitPane.setOneTouchExpandable(true);
        return splitPane;
    }

    private JScrollPane wrap(JTextArea area) {
        JScrollPane scrollPane = new JScrollPane(area);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        return scrollPane;
    }

    private JTextArea buildTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(false);
        area.setFont(MONO);
        return area;
    }

    private void loadExportFromDisk() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Open BLANCHE JSON");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        int selection = chooser.showOpenDialog(rootPanel);
        if (selection != JFileChooser.APPROVE_OPTION) {
            return;
        }

        Path selectedPath = chooser.getSelectedFile().toPath();
        try {
            routeLoadedJson(selectedPath, Files.readString(selectedPath));
        } catch (IOException exception) {
            statusLabel.setText("Failed to read " + selectedPath.getFileName());
            api.logging().logToError("BLANCHE failed to read JSON: " + exception.getMessage());
        }
    }

    private void routeLoadedJson(Path selectedPath, String rawJson) throws IOException {
        JsonNode root = objectMapper.readTree(rawJson);
        String sourceLabel = "Manual file import: " + selectedPath.getFileName();
        String kind = root.path("kind").asText("");

        switch (kind) {
            case "blanche.export":
                ingestBrowserExport(rawJson, sourceLabel);
                break;
            case "blanche.osint-seed":
                ingestOsintSeed(rawJson, sourceLabel);
                break;
            case "blanche.osint-report":
                ingestOsintReport(rawJson, sourceLabel);
                break;
            default:
                throw new IOException("Unsupported BLANCHE JSON kind: " + kind);
        }
    }

    private BlancheSiteMapIntegrator.IntegrationResult integrateIntoSiteMap(JsonNode root) {
        try {
            return siteMapIntegrator.integrate(root);
        } catch (RuntimeException exception) {
            api.logging().logToError("BLANCHE failed to update the site map: " + exception.getMessage());
            return new BlancheSiteMapIntegrator.IntegrationResult(
                root.at("/page/url").asText(""),
                0,
                "unknown",
                false,
                false,
                0,
                false,
                "Site map annotation failed: " + exception.getMessage()
            );
        }
    }

    private void clearViews() {
        registry.clear();
        rebuildTree(null, null, null);
        hostArea.setText("Cleared. Ingest a browser export or OSINT payload to populate the host tree again.");
        summaryArea.setText("");
        artifactsArea.setText("");
        storageArea.setText("");
        provenanceArea.setText("");
        trafficLedgerArea.setText("");
        pageRawArea.setText("");
        endpointArea.setText("");
        endpointRawArea.setText("");
        osintSeedArea.setText("");
        osintSeedRawArea.setText("");
        osintSummaryArea.setText("");
        osintFindingsArea.setText("");
        osintReportRawArea.setText("");
        detailTabs.removeAll();
        detailTabs.addTab("Details", wrap(hostArea));
        detailTabs.revalidate();
        detailTabs.repaint();
        statusLabel.setText("Cleared loaded export.");
        osintStatusLabel.setText("Cleared loaded OSINT data.");
    }

    // ------------------------------------------------------------------
    // Host/endpoint tree
    // ------------------------------------------------------------------

    private void rebuildTree(String selectHostname, NodeKind selectKind, String selectKey) {
        BlancheNode root = new BlancheNode(NodeKind.ROOT, null, null, "BLANCHE Hosts");
        for (String hostname : registry.hostnames()) {
            BlancheHostRegistry.HostSnapshot host = registry.host(hostname);
            if (host == null) {
                continue;
            }

            BlancheNode hostNode = new BlancheNode(NodeKind.HOST, hostname, null, treeHostLabel(host));
            root.add(hostNode);

            if (!host.pages().isEmpty()) {
                BlancheNode pagesFolder = new BlancheNode(
                    NodeKind.PAGES_FOLDER,
                    hostname,
                    null,
                    "Pages (" + host.pages().size() + ")"
                );
                for (BlancheHostRegistry.PageEntry page : host.pages()) {
                    pagesFolder.add(
                        new BlancheNode(NodeKind.PAGE, hostname, String.valueOf(page.id()), treePageLabel(page))
                    );
                }
                hostNode.add(pagesFolder);
            }

            if (!host.endpoints().isEmpty()) {
                BlancheNode endpointsFolder = new BlancheNode(
                    NodeKind.ENDPOINTS_FOLDER,
                    hostname,
                    null,
                    "Chromium-only endpoints (" + host.endpoints().size() + ")"
                );
                for (BlancheHostRegistry.EndpointEntry endpoint : host.endpoints()) {
                    endpointsFolder.add(
                        new BlancheNode(NodeKind.ENDPOINT, hostname, endpoint.key(), treeEndpointLabel(endpoint))
                    );
                }
                hostNode.add(endpointsFolder);
            }

            if (host.osintSeed() != null) {
                hostNode.add(new BlancheNode(NodeKind.OSINT_SEED, hostname, null, "OSINT Seed"));
            }
            if (host.osintReport() != null) {
                hostNode.add(new BlancheNode(NodeKind.OSINT_REPORT, hostname, null, "OSINT Report"));
            }
        }

        treeModel.setRoot(root);
        for (int row = 0; row < hostTree.getRowCount(); row++) {
            hostTree.expandRow(row);
        }

        BlancheNode target = findNode(root, selectHostname, selectKind, selectKey);
        if (target != null) {
            TreePath path = new TreePath(target.getPath());
            hostTree.setSelectionPath(path);
            hostTree.scrollPathToVisible(path);
        }
    }

    private static BlancheNode findNode(BlancheNode root, String hostname, NodeKind kind, String key) {
        if (hostname == null || kind == null) {
            return null;
        }

        Enumeration<?> hosts = root.children();
        while (hosts.hasMoreElements()) {
            BlancheNode hostNode = (BlancheNode) hosts.nextElement();
            if (!hostname.equals(hostNode.hostname)) {
                continue;
            }
            if (kind == NodeKind.HOST) {
                return hostNode;
            }

            Enumeration<?> folders = hostNode.children();
            while (folders.hasMoreElements()) {
                BlancheNode folderNode = (BlancheNode) folders.nextElement();
                if (folderNode.kind == kind && (key == null || key.equals(folderNode.key))) {
                    return folderNode;
                }

                Enumeration<?> leaves = folderNode.children();
                while (leaves.hasMoreElements()) {
                    BlancheNode leafNode = (BlancheNode) leaves.nextElement();
                    if (leafNode.kind == kind && (key == null || key.equals(leafNode.key))) {
                        return leafNode;
                    }
                }
            }
        }

        return null;
    }

    private void renderNode(BlancheNode node) {
        switch (node.kind) {
            case HOST -> renderHostNode(node.hostname);
            case PAGE -> renderPageNode(node.hostname, node.key);
            case ENDPOINT -> renderEndpointNode(node.hostname, node.key);
            case OSINT_SEED -> renderOsintSeedNode(node.hostname);
            case OSINT_REPORT -> renderOsintReportNode(node.hostname);
            default -> renderEmptyNode();
        }
    }

    private void renderEmptyNode() {
        detailTabs.removeAll();
        detailTabs.addTab("Details", wrap(hostArea));
        hostArea.setText("Select a host, page, Chromium-only endpoint, or OSINT node from the tree.");
    }

    private void renderHostNode(String hostname) {
        detailTabs.removeAll();
        detailTabs.addTab("Host Overview", wrap(hostArea));
        BlancheHostRegistry.HostSnapshot host = registry.host(hostname);
        hostArea.setText(host == null ? "No data for host " + hostname : renderHostOverview(host));
    }

    private void renderPageNode(String hostname, String pageIdKey) {
        detailTabs.removeAll();
        detailTabs.addTab("Summary", wrap(summaryArea));
        detailTabs.addTab("Artifacts", wrap(artifactsArea));
        detailTabs.addTab("Storage", wrap(storageArea));
        detailTabs.addTab("Blob Provenance", wrap(provenanceArea));
        detailTabs.addTab("Traffic Ledger", wrap(trafficLedgerArea));
        detailTabs.addTab("Raw JSON", wrap(pageRawArea));

        BlancheHostRegistry.HostSnapshot host = registry.host(hostname);
        BlancheHostRegistry.PageEntry page = findPage(host, pageIdKey);
        if (page == null) {
            summaryArea.setText("This page is no longer available.");
            artifactsArea.setText("");
            storageArea.setText("");
            provenanceArea.setText("");
            trafficLedgerArea.setText("");
            pageRawArea.setText("");
            return;
        }

        BlancheTrafficLedger.LedgerView trafficLedger = BlancheTrafficLedger.parse(page.root());
        summaryArea.setText(renderSummary(page, trafficLedger));
        artifactsArea.setText(renderArtifacts(page.root()));
        storageArea.setText(renderStorage(page.root()));
        provenanceArea.setText(renderBlobProvenance(page.root()));
        trafficLedgerArea.setText(BlancheTrafficLedger.render(trafficLedger));
        trafficLedgerArea.setCaretPosition(0);
        pageRawArea.setText(page.prettyJson());
        pageRawArea.setCaretPosition(0);
    }

    private void renderEndpointNode(String hostname, String key) {
        detailTabs.removeAll();
        detailTabs.addTab("Endpoint Artifacts", wrap(endpointArea));
        detailTabs.addTab("Raw JSON", wrap(endpointRawArea));

        BlancheHostRegistry.HostSnapshot host = registry.host(hostname);
        BlancheHostRegistry.EndpointEntry endpoint = findEndpoint(host, key);
        if (endpoint == null) {
            endpointArea.setText("This endpoint is no longer available.");
            endpointRawArea.setText("");
            return;
        }

        endpointArea.setText(renderEndpointArtifacts(hostname, endpoint));
        endpointRawArea.setText(renderEndpointRawJson(endpoint));
        endpointRawArea.setCaretPosition(0);
    }

    private void renderOsintSeedNode(String hostname) {
        detailTabs.removeAll();
        detailTabs.addTab("OSINT Seed", wrap(osintSeedArea));
        detailTabs.addTab("Raw JSON", wrap(osintSeedRawArea));

        BlancheHostRegistry.HostSnapshot host = registry.host(hostname);
        BlancheHostRegistry.OsintSeedEntry seed = host == null ? null : host.osintSeed();
        if (seed == null) {
            osintSeedArea.setText("No OSINT seed recorded for this host.");
            osintSeedRawArea.setText("");
            return;
        }

        osintSeedArea.setText(renderOsintSeed(seed));
        osintSeedRawArea.setText(seed.prettyJson());
        osintSeedRawArea.setCaretPosition(0);
    }

    private void renderOsintReportNode(String hostname) {
        detailTabs.removeAll();
        detailTabs.addTab("OSINT Summary", wrap(osintSummaryArea));
        detailTabs.addTab("OSINT Findings", wrap(osintFindingsArea));
        detailTabs.addTab("Raw JSON", wrap(osintReportRawArea));

        BlancheHostRegistry.HostSnapshot host = registry.host(hostname);
        BlancheHostRegistry.OsintReportEntry report = host == null ? null : host.osintReport();
        if (report == null) {
            osintSummaryArea.setText("No OSINT report recorded for this host.");
            osintFindingsArea.setText("");
            osintReportRawArea.setText("");
            return;
        }

        osintSummaryArea.setText(renderOsintSummary(report));
        osintFindingsArea.setText(renderOsintFindings(report.root()));
        osintReportRawArea.setText(report.prettyJson());
        osintReportRawArea.setCaretPosition(0);
    }

    private static BlancheHostRegistry.PageEntry findPage(BlancheHostRegistry.HostSnapshot host, String pageIdKey) {
        if (host == null || pageIdKey == null) {
            return null;
        }
        for (BlancheHostRegistry.PageEntry page : host.pages()) {
            if (String.valueOf(page.id()).equals(pageIdKey)) {
                return page;
            }
        }
        return null;
    }

    private static BlancheHostRegistry.EndpointEntry findEndpoint(BlancheHostRegistry.HostSnapshot host, String key) {
        if (host == null || key == null) {
            return null;
        }
        for (BlancheHostRegistry.EndpointEntry endpoint : host.endpoints()) {
            if (endpoint.key().equals(key)) {
                return endpoint;
            }
        }
        return null;
    }

    private static String treeHostLabel(BlancheHostRegistry.HostSnapshot host) {
        int chromiumOnlyTotal = 0;
        for (BlancheHostRegistry.EndpointEntry endpoint : host.endpoints()) {
            chromiumOnlyTotal += endpoint.artifacts().size();
        }
        return host.hostname() + "  [pages=" + host.pages().size() + ", chromium-only=" + chromiumOnlyTotal + "]";
    }

    private static String treePageLabel(BlancheHostRegistry.PageEntry page) {
        String title = page.title().isBlank() ? "(untitled)" : page.title();
        return abbreviate(title, 40) + "  " + abbreviate(page.pageUrl(), 60) + "  [" + page.exportedAt() + "]";
    }

    private static String treeEndpointLabel(BlancheHostRegistry.EndpointEntry endpoint) {
        String syntheticMarker = "/" + BlancheArtifactPairing.SYNTHETIC_SEGMENT + "/";
        String display = endpoint.key().contains(syntheticMarker)
            ? "(" + endpoint.category() + " @ origin)"
            : endpoint.key();
        return abbreviate(display, 70) + "  [" + endpoint.artifacts().size() + "]";
    }

    private enum NodeKind {
        ROOT,
        HOST,
        PAGES_FOLDER,
        PAGE,
        ENDPOINTS_FOLDER,
        ENDPOINT,
        OSINT_SEED,
        OSINT_REPORT
    }

    private static final class BlancheNode extends DefaultMutableTreeNode {
        final NodeKind kind;
        final String hostname;
        final String key;

        BlancheNode(NodeKind kind, String hostname, String key, String label) {
            super(label);
            this.kind = kind;
            this.hostname = hostname;
            this.key = key;
        }
    }

    // ------------------------------------------------------------------
    // Rendering
    // ------------------------------------------------------------------

    private String renderHostOverview(BlancheHostRegistry.HostSnapshot host) {
        StringBuilder builder = new StringBuilder();
        builder.append("Host: ").append(host.hostname()).append('\n');
        builder.append("Pages ingested: ").append(host.pages().size()).append('\n');
        builder.append("Chromium-only endpoints/buckets: ").append(host.endpoints().size()).append('\n');

        int totalChromiumOnly = 0;
        Map<String, Integer> byCategory = new LinkedHashMap<>();
        for (BlancheHostRegistry.EndpointEntry endpoint : host.endpoints()) {
            totalChromiumOnly += endpoint.artifacts().size();
            byCategory.merge(endpoint.category(), endpoint.artifacts().size(), Integer::sum);
        }
        builder.append("Chromium-only artifacts observed: ").append(totalChromiumOnly).append('\n');
        builder.append("By category: ").append(formatCategoryCounts(byCategory)).append('\n');
        builder.append("OSINT seed: ").append(host.osintSeed() != null ? "yes" : "no").append('\n');
        builder.append("OSINT report: ")
            .append(host.osintReport() != null ? "yes (" + host.osintReport().findingCount() + " findings)" : "no")
            .append('\n');
        builder.append('\n');

        builder.append("Pages\n");
        for (BlancheHostRegistry.PageEntry page : host.pages()) {
            builder.append("- ")
                .append(abbreviate(page.pageUrl(), 90))
                .append(" | ")
                .append(page.exportedAt())
                .append(" | chromium-only=")
                .append(page.chromiumOnlyCount())
                .append(" (")
                .append(page.chromiumOnlySummary())
                .append(") | ")
                .append(page.sourceLabel())
                .append('\n');
        }
        if (host.pages().isEmpty()) {
            builder.append("- No pages ingested for this host yet.\n");
        }

        builder.append('\n');
        builder.append("Chromium-only endpoints/buckets\n");
        for (BlancheHostRegistry.EndpointEntry endpoint : host.endpoints()) {
            builder.append("- ")
                .append(abbreviate(endpoint.key(), 90))
                .append(" | category=")
                .append(endpoint.category())
                .append(" | artifacts=")
                .append(endpoint.artifacts().size())
                .append('\n');
        }
        if (host.endpoints().isEmpty()) {
            builder.append("- No Chromium-only artifacts observed for this host yet.\n");
        }

        return builder.toString();
    }

    private String renderSummary(
        BlancheHostRegistry.PageEntry page,
        BlancheTrafficLedger.LedgerView trafficLedger
    ) {
        JsonNode root = page.root();
        StringBuilder summary = new StringBuilder();
        summary.append("Schema: ").append(root.path("schemaVersion").asText("unknown")).append('\n');
        summary.append("Exported: ").append(page.exportedAt()).append('\n');
        summary.append("Module: ").append(root.at("/module/name").asText("unknown")).append('\n');
        summary.append("Page: ").append(page.pageUrl()).append('\n');
        summary.append("Title: ").append(page.title()).append('\n');
        summary.append("Origin: ").append(page.origin()).append('\n');
        summary.append("Mode: ").append(page.mode()).append('\n');
        summary.append("Source: ").append(page.sourceLabel()).append('\n');
        summary.append("Session: ").append(root.at("/collection/sessionId").asText("unknown")).append('\n');
        summary.append("Artifacts: ").append(page.artifactCount()).append('\n');
        summary.append("Chromium-Only Artifacts: ").append(page.chromiumOnlyCount()).append('\n');
        summary.append("Chromium-Only Categories: ").append(page.chromiumOnlySummary()).append('\n');
        summary.append("Warnings: ").append(root.at("/summary/warningCount").asInt(0)).append('\n');
        summary.append("Errors: ").append(root.at("/summary/errorCount").asInt(0)).append('\n');
        summary.append("Visibility Gaps: ").append(root.at("/summary/visibilityGapCount").asInt(0)).append('\n');
        if (trafficLedger.present()) {
            summary.append("Traffic Ledger Entries: ").append(trafficLedger.entryCount()).append('\n');
            summary.append("Scored Traffic Entries: ").append(trafficLedger.scoredEntryCount()).append('\n');
            summary.append("Highest Traffic Priority: ").append(trafficLedger.highestPriorityLabel()).append('\n');
            summary.append("Traffic priority ranks review value; it is not vulnerability severity.\n");
        } else {
            summary.append("Traffic Ledger: not included (legacy-compatible export).\n");
        }
        return summary.toString();
    }

    private String renderArtifacts(JsonNode root) {
        List<String> lines = new ArrayList<>();
        for (JsonNode artifact : root.path("artifacts")) {
            String category = artifact.path("category").asText("unknown");
            String kind = artifact.path("kind").asText("unknown");
            String url = artifact.path("url").asText("");
            String disposition = artifact.at("/provenance/disposition").asText("unknown");
            lines.add(category + " | " + kind + " | " + disposition + " | " + abbreviate(url, 180));
        }

        if (lines.isEmpty()) {
            return "No artifacts found in this page's export.";
        }

        return String.join("\n", lines);
    }

    private String renderStorage(JsonNode root) {
        List<String> lines = new ArrayList<>();
        for (JsonNode artifact : root.path("artifacts")) {
            String category = artifact.path("category").asText("");
            if (!"storage-key".equals(category) && !"indexeddb-database".equals(category) && !"cache".equals(category)) {
                continue;
            }

            lines.add(
                category
                    + " | "
                    + artifact.path("kind").asText("unknown")
                    + " | "
                    + abbreviate(artifact.path("url").asText(""), 160)
                    + " | "
                    + abbreviate(artifact.path("attributes").toString(), 220)
            );
        }

        if (lines.isEmpty()) {
            return "No storage-oriented artifacts were present in this page's export.";
        }

        return String.join("\n", lines);
    }

    private String renderBlobProvenance(JsonNode root) {
        List<String> lines = new ArrayList<>();
        for (JsonNode artifact : root.path("artifacts")) {
            boolean blobCategory = "blob".equals(artifact.path("category").asText());
            boolean blobUrl = artifact.path("url").asText("").startsWith("blob:");
            if (!blobCategory && !blobUrl) {
                continue;
            }

            lines.add(
                artifact.path("kind").asText("unknown")
                    + " | "
                    + artifact.at("/provenance/disposition").asText("unknown")
                    + " | "
                    + artifact.at("/provenance/confidence").asText("unknown")
                    + " | "
                    + abbreviate(artifact.at("/provenance/note").asText(""), 220)
                    + " | "
                    + abbreviate(artifact.path("url").asText(""), 160)
            );
        }

        if (lines.isEmpty()) {
            return "No blob-oriented artifacts were present in this page's export.";
        }

        return String.join("\n", lines);
    }

    private String renderEndpointArtifacts(String hostname, BlancheHostRegistry.EndpointEntry endpoint) {
        StringBuilder builder = new StringBuilder();
        builder.append("Host: ").append(hostname).append('\n');
        builder.append("Endpoint/Bucket: ").append(endpoint.key()).append('\n');
        builder.append("Category: ").append(endpoint.category()).append('\n');
        builder.append("Observed artifacts: ").append(endpoint.artifacts().size()).append('\n');
        builder.append('\n');

        for (BlancheHostRegistry.ArtifactRef artifact : endpoint.artifacts()) {
            builder.append(artifact.kind())
                .append(" | ")
                .append(artifact.disposition())
                .append('/')
                .append(artifact.confidence())
                .append(" | page=")
                .append(abbreviate(artifact.pageUrl(), 80))
                .append(" | observed=")
                .append(artifact.observedAt())
                .append(" | source=")
                .append(artifact.sourceLabel());
            if (!artifact.url().isBlank()) {
                builder.append(" | url=").append(abbreviate(artifact.url(), 120));
            }
            if (!artifact.note().isBlank()) {
                builder.append(" | note=").append(abbreviate(artifact.note(), 160));
            }
            builder.append('\n');
        }

        if (endpoint.artifacts().isEmpty()) {
            builder.append("No artifacts recorded for this endpoint.\n");
        }

        return builder.toString();
    }

    private String renderEndpointRawJson(BlancheHostRegistry.EndpointEntry endpoint) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (BlancheHostRegistry.ArtifactRef artifact : endpoint.artifacts()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("category", artifact.category());
            item.put("kind", artifact.kind());
            item.put("url", artifact.url());
            item.put("disposition", artifact.disposition());
            item.put("confidence", artifact.confidence());
            item.put("note", artifact.note());
            item.put("pageUrl", artifact.pageUrl());
            item.put("pageTitle", artifact.pageTitle());
            item.put("sourceLabel", artifact.sourceLabel());
            item.put("observedAt", artifact.observedAt());
            items.add(item);
        }

        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(items);
        } catch (JsonProcessingException exception) {
            return "[]";
        }
    }

    private String renderOsintSeed(BlancheHostRegistry.OsintSeedEntry seed) {
        JsonNode root = seed.root();
        StringBuilder builder = new StringBuilder();
        builder.append("Seed Source: ").append(seed.sourceLabel()).append('\n');
        builder.append("Created: ").append(root.at("/seedMetadata/createdAt").asText("unknown")).append('\n');
        builder.append("Primary Hostname: ").append(root.at("/seed/primaryHostname").asText("unknown")).append('\n');
        builder.append("Target URL: ").append(root.at("/seed/targetUrl").asText("unknown")).append('\n');
        builder.append("Target Origin: ").append(root.at("/seed/targetOrigin").asText("unknown")).append('\n');
        builder.append("Apparent Root Domain: ")
            .append(root.at("/seed/apparentRootDomain").asText("unknown"))
            .append('\n');
        builder.append("Related Host Count: ").append(seed.relatedHostCount()).append('\n');
        builder.append('\n');
        builder.append("Related Hosts\n");
        for (JsonNode host : root.at("/browserContext/relatedHosts")) {
            builder.append("- ")
                .append(host.path("hostname").asText("unknown"))
                .append(" [")
                .append(host.path("sourceType").asText("unknown"))
                .append("]")
                .append('\n');
        }

        if (root.at("/browserContext/relatedHosts").isEmpty()) {
            builder.append("- No related browser-derived hosts were captured.\n");
        }

        builder.append('\n');
        builder.append("Guardrails\n");
        for (JsonNode line : root.at("/scope/disallowedActivities")) {
            builder.append("- ").append(line.asText("")).append('\n');
        }
        return builder.toString();
    }

    private String renderOsintSummary(BlancheHostRegistry.OsintReportEntry report) {
        JsonNode root = report.root();
        StringBuilder builder = new StringBuilder();
        builder.append("Schema: ").append(root.path("schemaVersion").asText("unknown")).append('\n');
        builder.append("Generated: ").append(root.at("/reportMetadata/generatedAt").asText("unknown")).append('\n');
        builder.append("Source: ").append(report.sourceLabel()).append('\n');
        builder.append("Primary Hostname: ").append(root.at("/target/primaryHostname").asText("unknown")).append('\n');
        builder.append("Target URL: ").append(root.at("/target/targetUrl").asText("unknown")).append('\n');
        builder.append("Findings: ").append(report.findingCount()).append('\n');
        builder.append("Completed Tools: ").append(root.at("/summary/completedTools").asInt(0)).append('\n');
        builder.append("Skipped Tools: ").append(root.at("/summary/skippedTools").asInt(0)).append('\n');
        builder.append("Failed Tools: ").append(root.at("/summary/failedTools").asInt(0)).append('\n');
        builder.append('\n');
        builder.append(root.at("/narrative/headline").asText("(no narrative headline)")).append('\n');
        builder.append(root.at("/narrative/summary").asText("(no narrative summary)")).append('\n');
        builder.append('\n');
        builder.append("Follow-On Focus\n");
        for (JsonNode line : root.at("/narrative/followOnFocus")) {
            builder.append("- ").append(line.asText("")).append('\n');
        }
        builder.append('\n');
        builder.append("Tool Executions\n");
        for (JsonNode tool : root.path("toolExecutions")) {
            builder.append("- ")
                .append(tool.path("name").asText("unknown"))
                .append(" [")
                .append(tool.path("status").asText("unknown"))
                .append("] outputs=")
                .append(tool.path("outputCount").asInt(0))
                .append(" target=")
                .append(tool.path("target").asText("unknown"))
                .append('\n');
        }
        return builder.toString();
    }

    private String renderOsintFindings(JsonNode root) {
        List<String> lines = new ArrayList<>();
        for (JsonNode finding : root.path("findings")) {
            lines.add(
                finding.path("category").asText("unknown")
                    + " | "
                    + finding.path("title").asText("unknown")
                    + " | "
                    + finding.path("target").asText("unknown")
                    + " | "
                    + abbreviate(finding.path("description").asText(""), 240)
            );
        }

        if (lines.isEmpty()) {
            return "No normalized OSINT findings were present in the loaded report.";
        }

        return String.join("\n", lines);
    }

    private static String formatCategoryCounts(Map<String, Integer> counts) {
        if (counts.isEmpty()) {
            return "none";
        }
        List<String> parts = new ArrayList<>();
        counts.forEach((category, count) -> parts.add(category + "=" + count));
        return String.join(", ", parts);
    }

    private static String abbreviate(String value, int maxLength) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        return value.length() <= maxLength ? value : value.substring(0, maxLength) + "...";
    }

    private static String buildStatusLine(IngestionResult result) {
        String pageLabel = result.pageUrl().isBlank() ? "(unknown page)" : abbreviate(result.pageUrl(), 120);
        return "Loaded " + pageLabel + " via " + result.sourceLabel() + ". " + result.siteMapStatus();
    }

    public record IngestionResult(
        String sourceLabel,
        String pageUrl,
        int artifactCount,
        int chromiumOnlyArtifactCount,
        boolean highlightedInSiteMap,
        String siteMapStatus
    ) {}

    public record OsintSeedResult(
        String sourceLabel,
        String primaryHostname,
        int relatedHostCount
    ) {}

    public record OsintReportResult(
        String sourceLabel,
        String primaryHostname,
        int findingCount
    ) {}
}
