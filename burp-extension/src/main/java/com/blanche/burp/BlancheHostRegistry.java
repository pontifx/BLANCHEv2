package com.blanche.burp;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * In-memory model that aggregates every ingested browser export and OSINT payload by hostname,
 * and further buckets Chromium-only artifacts by the specific endpoint (or synthetic per-host
 * bucket) they belong to. This is what lets the suite tab show paired data per host/endpoint
 * instead of overwriting a single set of views with whatever was ingested most recently.
 */
public final class BlancheHostRegistry {
    private static final int MAX_PAGES_PER_HOST = 50;
    private static final int MAX_ARTIFACTS_PER_ENDPOINT = 200;
    private static final String UNKNOWN_HOST = "(unknown host)";

    private final Map<String, HostRecord> hosts = new LinkedHashMap<>();
    private long nextPageId = 1;

    public synchronized PageIngestSummary recordExport(JsonNode root, String prettyJson, String sourceLabel) {
        String pageUrl = root.at("/page/url").asText("");
        String hostname = normalizeHostname(BlancheArtifactPairing.hostnameOf(pageUrl));
        HostRecord host = hosts.computeIfAbsent(hostname, HostRecord::new);

        Map<String, Integer> chromiumOnlyCounts = new LinkedHashMap<>();
        int chromiumOnlyCount = 0;
        for (JsonNode artifact : root.path("artifacts")) {
            if (!BlancheArtifactPairing.isChromiumOnly(artifact)) {
                continue;
            }

            String category = artifact.path("category").asText("unknown");
            chromiumOnlyCounts.merge(category, 1, Integer::sum);
            chromiumOnlyCount++;

            String endpointHostname = normalizeHostname(BlancheArtifactPairing.pairingHostname(artifact, pageUrl));
            HostRecord endpointHost = hosts.computeIfAbsent(endpointHostname, HostRecord::new);
            String key = BlancheArtifactPairing.pairingKey(artifact, pageUrl);
            MutableEndpoint endpoint = endpointHost.endpoints.computeIfAbsent(key, k -> new MutableEndpoint(k, category));
            endpoint.artifacts.add(
                0,
                new ArtifactRef(
                    category,
                    artifact.path("kind").asText("unknown"),
                    artifact.path("url").asText(""),
                    artifact.at("/provenance/disposition").asText("unknown"),
                    artifact.at("/provenance/confidence").asText("unknown"),
                    artifact.at("/provenance/note").asText(""),
                    artifact.path("attributes").toString(),
                    pageUrl,
                    root.at("/page/title").asText(""),
                    sourceLabel,
                    root.at("/exportMetadata/exportedAt").asText("")
                )
            );
            trimToMax(endpoint.artifacts, MAX_ARTIFACTS_PER_ENDPOINT);
        }

        PageEntry page = new PageEntry(
            nextPageId++,
            pageUrl,
            root.at("/page/title").asText(""),
            root.at("/page/origin").asText(""),
            root.at("/page/referrer").asText(""),
            sourceLabel,
            root.at("/exportMetadata/exportedAt").asText(""),
            root.at("/collection/mode").asText("unknown"),
            root.at("/summary/artifactCount").asInt(0),
            chromiumOnlyCount,
            summarizeCounts(chromiumOnlyCounts),
            root,
            prettyJson
        );
        host.pages.add(0, page);
        trimToMax(host.pages, MAX_PAGES_PER_HOST);

        return new PageIngestSummary(hostname, pageUrl, page.id(), chromiumOnlyCount, page.chromiumOnlySummary());
    }

    public synchronized OsintSeedIngestSummary recordOsintSeed(JsonNode root, String prettyJson, String sourceLabel) {
        String primaryHostname = root.at("/seed/primaryHostname").asText("");
        String fallbackHostname = BlancheArtifactPairing.hostnameOf(root.at("/seed/targetUrl").asText(""));
        String hostname = normalizeHostname(primaryHostname.isBlank() ? fallbackHostname : primaryHostname);
        int relatedHostCount = root.at("/browserContext/relatedHosts").size();

        HostRecord host = hosts.computeIfAbsent(hostname, HostRecord::new);
        host.osintSeed = new OsintSeedEntry(root, prettyJson, sourceLabel, primaryHostname, relatedHostCount);

        return new OsintSeedIngestSummary(hostname, primaryHostname, relatedHostCount);
    }

    public synchronized OsintReportIngestSummary recordOsintReport(JsonNode root, String prettyJson, String sourceLabel) {
        String primaryHostname = root.at("/target/primaryHostname").asText("");
        String fallbackHostname = BlancheArtifactPairing.hostnameOf(root.at("/target/targetUrl").asText(""));
        String hostname = normalizeHostname(primaryHostname.isBlank() ? fallbackHostname : primaryHostname);
        int findingCount = root.at("/summary/findingCount").asInt(root.path("findings").size());

        HostRecord host = hosts.computeIfAbsent(hostname, HostRecord::new);
        host.osintReport = new OsintReportEntry(root, prettyJson, sourceLabel, primaryHostname, findingCount);

        return new OsintReportIngestSummary(hostname, primaryHostname, findingCount);
    }

    public synchronized List<String> hostnames() {
        return hosts.keySet()
            .stream()
            .sorted(String.CASE_INSENSITIVE_ORDER)
            .collect(Collectors.toList());
    }

    public synchronized HostSnapshot host(String hostname) {
        HostRecord record = hosts.get(hostname);
        if (record == null) {
            return null;
        }

        List<EndpointEntry> endpoints = new ArrayList<>();
        for (MutableEndpoint endpoint : record.endpoints.values()) {
            endpoints.add(new EndpointEntry(endpoint.key, endpoint.category, List.copyOf(endpoint.artifacts)));
        }

        return new HostSnapshot(
            record.hostname,
            List.copyOf(record.pages),
            endpoints,
            record.osintSeed,
            record.osintReport
        );
    }

    public synchronized void clear() {
        hosts.clear();
    }

    private static String normalizeHostname(String hostname) {
        if (hostname == null || hostname.isBlank()) {
            return UNKNOWN_HOST;
        }
        return hostname.toLowerCase(Locale.ROOT);
    }

    private static String summarizeCounts(Map<String, Integer> counts) {
        if (counts.isEmpty()) {
            return "none";
        }
        return counts.entrySet()
            .stream()
            .sorted((left, right) -> {
                int countComparison = Integer.compare(right.getValue(), left.getValue());
                return countComparison != 0 ? countComparison : left.getKey().compareTo(right.getKey());
            })
            .map(entry -> entry.getKey() + "=" + entry.getValue())
            .collect(Collectors.joining(", "));
    }

    private static <T> void trimToMax(List<T> list, int max) {
        while (list.size() > max) {
            list.remove(list.size() - 1);
        }
    }

    private static final class HostRecord {
        final String hostname;
        final List<PageEntry> pages = new ArrayList<>();
        final Map<String, MutableEndpoint> endpoints = new LinkedHashMap<>();
        OsintSeedEntry osintSeed;
        OsintReportEntry osintReport;

        HostRecord(String hostname) {
            this.hostname = hostname;
        }
    }

    private static final class MutableEndpoint {
        final String key;
        final String category;
        final List<ArtifactRef> artifacts = new ArrayList<>();

        MutableEndpoint(String key, String category) {
            this.key = key;
            this.category = category;
        }
    }

    public record PageEntry(
        long id,
        String pageUrl,
        String title,
        String origin,
        String referrer,
        String sourceLabel,
        String exportedAt,
        String mode,
        int artifactCount,
        int chromiumOnlyCount,
        String chromiumOnlySummary,
        JsonNode root,
        String prettyJson
    ) {}

    public record ArtifactRef(
        String category,
        String kind,
        String url,
        String disposition,
        String confidence,
        String note,
        String attributesJson,
        String pageUrl,
        String pageTitle,
        String sourceLabel,
        String observedAt
    ) {}

    public record EndpointEntry(String key, String category, List<ArtifactRef> artifacts) {}

    public record OsintSeedEntry(
        JsonNode root,
        String prettyJson,
        String sourceLabel,
        String primaryHostname,
        int relatedHostCount
    ) {}

    public record OsintReportEntry(
        JsonNode root,
        String prettyJson,
        String sourceLabel,
        String primaryHostname,
        int findingCount
    ) {}

    public record HostSnapshot(
        String hostname,
        List<PageEntry> pages,
        List<EndpointEntry> endpoints,
        OsintSeedEntry osintSeed,
        OsintReportEntry osintReport
    ) {}

    public record PageIngestSummary(
        String hostname,
        String pageUrl,
        long pageId,
        int chromiumOnlyCount,
        String chromiumOnlySummary
    ) {}

    public record OsintSeedIngestSummary(String hostname, String primaryHostname, int relatedHostCount) {}

    public record OsintReportIngestSummary(String hostname, String primaryHostname, int findingCount) {}
}
