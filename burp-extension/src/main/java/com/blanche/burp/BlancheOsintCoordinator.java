package com.blanche.burp;

import burp.api.montoya.MontoyaApi;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class BlancheOsintCoordinator {
    private final MontoyaApi api;
    private final BlancheSuiteTab suiteTab;
    private final BlancheOsintCliRunner cliRunner;
    private final ExecutorService worker = Executors.newSingleThreadExecutor((runnable) -> {
        Thread thread = new Thread(runnable, "blanche-osint-coordinator");
        thread.setDaemon(true);
        return thread;
    });

    private volatile String lastSeedJson;

    public BlancheOsintCoordinator(MontoyaApi api, BlancheSuiteTab suiteTab) {
        this.api = api;
        this.suiteTab = suiteTab;
        this.cliRunner = new BlancheOsintCliRunner(api);
    }

    public String availabilitySummary() {
        return cliRunner.describeAvailability();
    }

    public BlancheSuiteTab.OsintSeedResult ingestSeed(String rawJson, String sourceLabel) throws IOException {
        lastSeedJson = rawJson;
        BlancheSuiteTab.OsintSeedResult result = suiteTab.ingestOsintSeed(rawJson, sourceLabel);
        suiteTab.setOsintStatus(
            "Stored OSINT seed for " + result.primaryHostname() + ". " + cliRunner.describeAvailability()
        );

        worker.execute(() -> runSeedInternal(rawJson, "Automated Burp OSINT orchestration"));
        return result;
    }

    public void runLastSeed() {
        String seedJson = lastSeedJson;
        if (seedJson == null || seedJson.isBlank()) {
            suiteTab.setOsintStatus("No OSINT seed is loaded yet.");
            return;
        }

        worker.execute(() -> runSeedInternal(seedJson, "Manual Burp OSINT orchestration"));
    }

    public void stop() {
        worker.shutdownNow();
    }

    private void runSeedInternal(String rawSeedJson, String sourceLabel) {
        suiteTab.setOsintStatus("Running OSINT orchestration...");
        BlancheOsintCliRunner.RunResult result = cliRunner.runSeed(rawSeedJson);
        if (!result.available()) {
            suiteTab.setOsintStatus(result.message());
            return;
        }

        if (!result.successful()) {
            suiteTab.setOsintStatus(result.message());
            api.logging().logToError("BLANCHE OSINT orchestration failed: " + result.message());
            return;
        }

        try {
            BlancheSuiteTab.OsintReportResult reportResult = suiteTab.ingestOsintReport(
                result.outputJson(),
                sourceLabel
            );
            suiteTab.setOsintStatus(
                "OSINT report ready for " + reportResult.primaryHostname() + " with "
                    + reportResult.findingCount() + " findings."
            );
            api.logging().logToOutput(
                "BLANCHE OSINT report ready for "
                    + reportResult.primaryHostname()
                    + " with "
                    + reportResult.findingCount()
                    + " findings."
            );
        } catch (IOException exception) {
            suiteTab.setOsintStatus("OSINT report ingestion failed: " + exception.getMessage());
            api.logging().logToError("BLANCHE could not ingest OSINT report: " + exception.getMessage());
        }
    }
}
