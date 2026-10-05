package com.blanche.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import java.util.ArrayList;
import java.util.List;

public final class BlancheBurpExtension implements BurpExtension {
    private static final String EMU_ASCII = String.join(
        System.lineSeparator(),
        "",
        "        __",
        "     .-(  )-.",
        "    /   oo   \\",
        "   |     ^    |",
        "    \\  \\___/ /",
        "     `-.   .-'",
        "       /|||\\",
        "      /_|||_\\",
        "        |||",
        "       / | \\",
        "      /__|__\\",
        "        EMU",
        "     BLANCHE"
    );

    private BlancheProxyBridge proxyBridge;
    private BlancheLoopbackBridge loopbackBridge;
    private BlancheOsintCoordinator osintCoordinator;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("BLANCHE");
        api.logging().logToOutput(EMU_ASCII);

        BlancheSuiteTab suiteTab = new BlancheSuiteTab(api);
        osintCoordinator = new BlancheOsintCoordinator(api, suiteTab);
        suiteTab.setRunOsintHandler(osintCoordinator::runLastSeed);
        suiteTab.setOsintStatus(osintCoordinator.availabilitySummary());
        api.userInterface().registerSuiteTab("BLANCHE", suiteTab.getComponent());

        List<String> activeEndpoints = new ArrayList<>();
        List<String> startupErrors = new ArrayList<>();

        try {
            proxyBridge = BlancheProxyBridge.start(api, suiteTab, osintCoordinator);
            api.logging().logToOutput("BLANCHE proxy ingest bridge registered for " + proxyBridge.endpoint());
            activeEndpoints.add("proxy " + proxyBridge.endpoint());
            activeEndpoints.add("proxy " + proxyBridge.osintSeedEndpoint());
            activeEndpoints.add("proxy " + proxyBridge.osintReportEndpoint());
        } catch (Exception exception) {
            api.logging().logToError("BLANCHE failed to start proxy ingest bridge: " + exception.getMessage());
            startupErrors.add("proxy bridge: " + exception.getMessage());
        }

        try {
            loopbackBridge = BlancheLoopbackBridge.start(api, suiteTab, osintCoordinator);
            api.logging().logToOutput("BLANCHE loopback ingest bridge listening on " + loopbackBridge.endpoint());
            activeEndpoints.add("loopback " + loopbackBridge.endpoint());
            activeEndpoints.add("loopback " + loopbackBridge.osintSeedEndpoint());
            activeEndpoints.add("loopback " + loopbackBridge.osintReportEndpoint());
        } catch (Exception exception) {
            api.logging().logToError("BLANCHE failed to start loopback ingest bridge: " + exception.getMessage());
            startupErrors.add("loopback bridge: " + exception.getMessage());
        }

        if (!activeEndpoints.isEmpty()) {
            suiteTab.setAutoIngestEndpoint(String.join(" | ", activeEndpoints));
            api.extension().registerUnloadingHandler(() -> {
                if (proxyBridge != null) {
                    proxyBridge.stop();
                }
                if (loopbackBridge != null) {
                    loopbackBridge.stop();
                }
                if (osintCoordinator != null) {
                    osintCoordinator.stop();
                }
            });
        } else {
            suiteTab.setAutoIngestStatus("Auto ingest unavailable: " + String.join(" | ", startupErrors));
        }

        api.logging().logToOutput("BLANCHE Burp extension initialized.");
    }
}
