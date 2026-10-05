package com.blanche.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class BlancheSiteMapIntegrator {
    private static final HighlightColor CHROMIUM_HIGHLIGHT = HighlightColor.CYAN;
    private static final String NOTE_START = "[BLANCHE]";
    private static final String NOTE_END = "[/BLANCHE]";
    private static final int MAX_ARTIFACTS_PER_NOTE = 15;

    private final MontoyaApi api;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public BlancheSiteMapIntegrator(MontoyaApi api) {
        this.api = api;
    }

    public IntegrationResult integrate(JsonNode root) {
        String pageUrl = normalizeSiteMapUrl(root.at("/page/url").asText(""));
        if (pageUrl.isBlank()) {
            return new IntegrationResult(
                "",
                0,
                "none",
                false,
                false,
                0,
                false,
                "Skipped site map annotation because the export did not include a usable page URL."
            );
        }

        Map<String, Integer> chromiumOnlyCounts = collectChromiumOnlyCounts(root.path("artifacts"));
        int chromiumOnlyArtifactCount = chromiumOnlyCounts.values().stream().mapToInt(Integer::intValue).sum();
        boolean highlighted = chromiumOnlyArtifactCount > 0;
        String chromiumOnlySummary = formatCounts(chromiumOnlyCounts);

        String managedNote = buildManagedNote(root, chromiumOnlyArtifactCount, chromiumOnlySummary);
        HttpRequestResponse existing = findManagedOrMatchingEntry(pageUrl);
        boolean syntheticEntry = existing == null;
        HttpRequestResponse siteMapEntry = syntheticEntry
            ? buildSyntheticEntry(root, pageUrl, managedNote, highlighted, chromiumOnlyArtifactCount, chromiumOnlyCounts)
            : existing.withAnnotations(buildAnnotations(existing.annotations(), managedNote, highlighted));

        api.siteMap().add(siteMapEntry);
        boolean sentToOrganizer = sendToOrganizer(siteMapEntry);

        int pairedEndpointCount = pairChromiumOnlyArtifactsToSiteTree(root, pageUrl);

        String statusMessage = syntheticEntry
            ? highlighted
                ? "Added a synthetic site map item and highlighted it cyan for Chromium-only visibility."
                : "Added a synthetic site map item without highlight because no Chromium-only artifacts were identified."
            : highlighted
                ? "Annotated an existing site map item and highlighted it cyan for Chromium-only visibility."
                : "Annotated an existing site map item without highlight because no Chromium-only artifacts were identified.";
        statusMessage += sentToOrganizer
            ? " Sent annotated page-state item to Organizer."
            : " Organizer handoff unavailable.";
        statusMessage += pairedEndpointCount > 0
            ? " Paired " + pairedEndpointCount + " Chromium-only endpoint(s)/bucket(s) into the site tree."
            : " No Chromium-only endpoints required pairing.";

        return new IntegrationResult(
            pageUrl,
            chromiumOnlyArtifactCount,
            chromiumOnlySummary,
            highlighted,
            syntheticEntry,
            pairedEndpointCount,
            sentToOrganizer,
            statusMessage
        );
    }

    /**
     * Groups Chromium-only artifacts by their paired host/endpoint key (see
     * {@link BlancheArtifactPairing}) and creates or annotates one site map entry per group, so
     * expanding a host in Burp's site tree surfaces the browser-only data captured for it instead
     * of a single flat page-level note.
     */
    private int pairChromiumOnlyArtifactsToSiteTree(JsonNode root, String pageUrl) {
        String rawPageUrl = root.at("/page/url").asText("");
        Map<String, List<JsonNode>> grouped = new LinkedHashMap<>();
        for (JsonNode artifact : root.path("artifacts")) {
            if (!BlancheArtifactPairing.isChromiumOnly(artifact)) {
                continue;
            }
            String key = BlancheArtifactPairing.pairingKey(artifact, rawPageUrl);
            grouped.computeIfAbsent(key, unused -> new ArrayList<>()).add(artifact);
        }

        int pairedCount = 0;
        for (Map.Entry<String, List<JsonNode>> entry : grouped.entrySet()) {
            String rawKey = entry.getKey();
            if (!rawKey.startsWith("http://") && !rawKey.startsWith("https://")) {
                continue;
            }

            String endpointUrl = normalizeSiteMapUrl(rawKey);
            if (endpointUrl.isBlank() || endpointUrl.equals(pageUrl)) {
                continue;
            }

            List<JsonNode> artifacts = entry.getValue();
            String note = buildEndpointNote(root, endpointUrl, artifacts);
            HttpRequestResponse existing = findManagedOrMatchingEntry(endpointUrl);
            HttpRequestResponse entryItem = existing == null
                ? buildEndpointSyntheticEntry(root, endpointUrl, note, artifacts)
                : existing.withAnnotations(buildAnnotations(existing.annotations(), note, true));

            api.siteMap().add(entryItem);
            sendToOrganizer(entryItem);
            pairedCount++;
        }

        return pairedCount;
    }

    private HttpRequestResponse findManagedOrMatchingEntry(String url) {
        HttpRequestResponse fallback = null;
        for (HttpRequestResponse candidate : api.siteMap().requestResponses()) {
            if (!url.equals(normalizeSiteMapUrl(candidate.request().url()))) {
                continue;
            }

            String notes = candidate.annotations().hasNotes() ? candidate.annotations().notes() : "";
            if (notes.contains(NOTE_START)) {
                return candidate;
            }

            if (fallback == null) {
                fallback = candidate;
            }
        }

        return fallback;
    }

    private HttpRequestResponse buildSyntheticEntry(
        JsonNode root,
        String pageUrl,
        String managedNote,
        boolean highlighted,
        int chromiumOnlyArtifactCount,
        Map<String, Integer> chromiumOnlyCounts
    ) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(pageUrl);
        HttpResponse response = HttpResponse.httpResponse(
            "HTTP/1.1 200 BLANCHE Observed\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n"
                + "X-BLANCHE-Schema-Version: "
                + root.path("schemaVersion").asText("unknown")
                + "\r\n"
                + "X-BLANCHE-Chromium-Only: "
                + chromiumOnlyArtifactCount
                + "\r\n"
                + "X-BLANCHE-Page-State: "
                + compactHeaderValue(root.path("page").path("title").asText("untitled"))
                + "; mode="
                + compactHeaderValue(root.at("/collection/mode").asText("unknown"))
                + "; chromiumOnly="
                + chromiumOnlyArtifactCount
                + "\r\n"
                + "\r\n"
                + buildSyntheticResponseBody(root, pageUrl, chromiumOnlyArtifactCount, chromiumOnlyCounts)
        );
        Annotations annotations = highlighted
            ? Annotations.annotations(managedNote, CHROMIUM_HIGHLIGHT)
            : Annotations.annotations(managedNote);
        return HttpRequestResponse.httpRequestResponse(request, response, annotations);
    }

    private HttpRequestResponse buildEndpointSyntheticEntry(
        JsonNode root,
        String endpointUrl,
        String managedNote,
        List<JsonNode> artifacts
    ) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(endpointUrl);
        HttpResponse response = HttpResponse.httpResponse(
            "HTTP/1.1 200 BLANCHE Observed\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n"
                + "X-BLANCHE-Chromium-Only: "
                + artifacts.size()
                + "\r\n"
                + "X-BLANCHE-Endpoint: "
                + compactHeaderValue(endpointUrl)
                + "\r\n"
                + "\r\n"
                + buildEndpointResponseBody(root, endpointUrl, artifacts)
        );
        Annotations annotations = Annotations.annotations(managedNote, CHROMIUM_HIGHLIGHT);
        return HttpRequestResponse.httpRequestResponse(request, response, annotations);
    }

    private String buildSyntheticResponseBody(
        JsonNode root,
        String pageUrl,
        int chromiumOnlyArtifactCount,
        Map<String, Integer> chromiumOnlyCounts
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("kind", "blanche.ingestion-summary");
        body.put("pageUrl", pageUrl);
        body.put("schemaVersion", root.path("schemaVersion").asText("unknown"));
        body.put("exportedAt", root.at("/exportMetadata/exportedAt").asText("unknown"));
        body.put("collectionMode", root.at("/collection/mode").asText("unknown"));
        body.put("artifactCount", root.at("/summary/artifactCount").asInt(0));
        body.put("chromiumOnlyArtifactCount", chromiumOnlyArtifactCount);
        body.put("chromiumOnlyCategories", chromiumOnlyCounts);
        body.put("pageState", buildPageStateSummary(root, chromiumOnlyArtifactCount, chromiumOnlyCounts));
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
        } catch (JsonProcessingException exception) {
            return "{\"kind\":\"blanche.ingestion-summary\",\"pageUrl\":\"" + pageUrl + "\"}";
        }
    }

    private String buildEndpointResponseBody(JsonNode root, String endpointUrl, List<JsonNode> artifacts) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("kind", "blanche.chromium-only-endpoint");
        body.put("endpoint", endpointUrl);
        body.put("sourcePageUrl", root.at("/page/url").asText(""));
        body.put("exportedAt", root.at("/exportMetadata/exportedAt").asText("unknown"));
        body.put("artifactCount", artifacts.size());

        List<Map<String, Object>> artifactBodies = new ArrayList<>();
        for (JsonNode artifact : artifacts) {
            Map<String, Object> artifactBody = new LinkedHashMap<>();
            artifactBody.put("category", artifact.path("category").asText("unknown"));
            artifactBody.put("kind", artifact.path("kind").asText("unknown"));
            artifactBody.put("url", artifact.path("url").asText(""));
            artifactBody.put("disposition", artifact.at("/provenance/disposition").asText("unknown"));
            artifactBody.put("confidence", artifact.at("/provenance/confidence").asText("unknown"));
            artifactBody.put("note", artifact.at("/provenance/note").asText(""));
            artifactBodies.add(artifactBody);
        }
        body.put("artifacts", artifactBodies);

        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(body);
        } catch (JsonProcessingException exception) {
            return "{\"kind\":\"blanche.chromium-only-endpoint\",\"endpoint\":\"" + endpointUrl + "\"}";
        }
    }

    private String buildManagedNote(JsonNode root, int chromiumOnlyArtifactCount, String chromiumOnlySummary) {
        StringBuilder note = new StringBuilder();
        note.append(NOTE_START);
        note.append("\nBLANCHE page state");
        note.append("\nPage: ").append(root.at("/page/url").asText("unknown"));
        note.append("\nTitle: ").append(root.at("/page/title").asText("unknown"));
        note.append("\nOrigin: ").append(root.at("/page/origin").asText("unknown"));
        note.append("\nReferrer: ").append(root.at("/page/referrer").asText("none"));
        note.append("\nExported: ").append(root.at("/exportMetadata/exportedAt").asText("unknown"));
        note.append("\nMode: ").append(root.at("/collection/mode").asText("unknown"));
        note.append("\nReload triggered: ").append(root.at("/collection/reloadTriggered").asBoolean(false));
        note.append("\nSession: ").append(root.at("/collection/sessionId").asText("unknown"));
        note.append("\nInitial URL: ").append(root.at("/collection/target/initialUrl").asText("unknown"));
        note.append("\nFinal URL: ").append(root.at("/collection/target/finalUrl").asText("unknown"));
        note.append("\nTab: id=").append(root.at("/page/tab/tabId").asText("unknown"))
            .append(" window=").append(root.at("/page/tab/windowId").asText("unknown"))
            .append(" status=").append(root.at("/page/tab/status").asText("unknown"))
            .append(" active=").append(root.at("/page/tab/active").asText("unknown"));
        note.append("\nFrames: ").append(root.at("/page/frames").size());
        appendFrameSummary(note, root.at("/page/frames"));
        note.append("\nArtifacts: ").append(root.at("/summary/artifactCount").asInt(0));
        note.append("\nChromium-only artifacts: ").append(chromiumOnlyArtifactCount);
        note.append("\nChromium-only categories: ").append(chromiumOnlySummary);
        note.append("\nBrowser storage: local/session keys=")
            .append(countArtifacts(root.path("artifacts"), "storage-key"))
            .append(" indexedDB=")
            .append(countArtifacts(root.path("artifacts"), "indexeddb-database"))
            .append(" cacheStorage=")
            .append(countArtifacts(root.path("artifacts"), "cache"));
        note.append("\nWorkers: serviceWorkers=")
            .append(countArtifacts(root.path("artifacts"), "service-worker"))
            .append(" workers=")
            .append(countArtifacts(root.path("artifacts"), "worker"));
        note.append("\nBlob/data/runtime: blobs=")
            .append(countArtifacts(root.path("artifacts"), "blob"))
            .append(" dataUrlArtifacts=")
            .append(countDataUrlArtifacts(root.path("artifacts")))
            .append(" runtimeIndicators=")
            .append(countArtifacts(root.path("artifacts"), "runtime-indicator"));
        note.append("\nCollectors: ").append(buildCollectorSummary(root.path("collectors")));
        note.append("\nWarnings/errors/gaps: ")
            .append(root.at("/summary/warningCount").asInt(0))
            .append("/")
            .append(root.at("/summary/errorCount").asInt(0))
            .append("/")
            .append(root.at("/summary/visibilityGapCount").asInt(0));
        note.append("\nChromium-only data for this page is also paired per-endpoint under this host in the site tree.");
        note.append("\n").append(NOTE_END);
        return note.toString();
    }

    private String buildEndpointNote(JsonNode root, String endpointUrl, List<JsonNode> artifacts) {
        Map<String, Integer> byCategory = new LinkedHashMap<>();
        for (JsonNode artifact : artifacts) {
            byCategory.merge(artifact.path("category").asText("unknown"), 1, Integer::sum);
        }

        StringBuilder note = new StringBuilder();
        note.append(NOTE_START);
        note.append("\nBLANCHE Chromium-only endpoint");
        note.append("\nEndpoint: ").append(endpointUrl);
        note.append("\nSource page: ").append(root.at("/page/url").asText("unknown"));
        note.append("\nExported: ").append(root.at("/exportMetadata/exportedAt").asText("unknown"));
        note.append("\nSession: ").append(root.at("/collection/sessionId").asText("unknown"));
        note.append("\nArtifact count: ").append(artifacts.size());
        note.append("\nCategories: ").append(formatCounts(byCategory));
        note.append("\nArtifacts:");

        int shown = 0;
        for (JsonNode artifact : artifacts) {
            if (shown >= MAX_ARTIFACTS_PER_NOTE) {
                note.append("\n  - ... ").append(artifacts.size() - shown).append(" more artifact(s)");
                break;
            }

            note.append("\n  - ")
                .append(artifact.path("kind").asText("unknown"))
                .append(" | ")
                .append(artifact.at("/provenance/disposition").asText("unknown"))
                .append("/")
                .append(artifact.at("/provenance/confidence").asText("unknown"));
            String artifactUrl = artifact.path("url").asText("");
            if (!artifactUrl.isBlank()) {
                note.append(" | ").append(compactHeaderValue(artifactUrl));
            }
            shown++;
        }

        note.append("\n").append(NOTE_END);
        return note.toString();
    }

    private boolean sendToOrganizer(HttpRequestResponse item) {
        try {
            api.organizer().sendToOrganizer(item);
            return true;
        } catch (Exception exception) {
            api.logging().logToOutput("BLANCHE Organizer handoff unavailable: " + exception.getMessage());
            return false;
        }
    }

    private Map<String, Object> buildPageStateSummary(
        JsonNode root,
        int chromiumOnlyArtifactCount,
        Map<String, Integer> chromiumOnlyCounts
    ) {
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("url", root.at("/page/url").asText(""));
        state.put("title", root.at("/page/title").asText(""));
        state.put("origin", root.at("/page/origin").asText(""));
        state.put("referrer", root.at("/page/referrer").asText(""));
        state.put("mode", root.at("/collection/mode").asText("unknown"));
        state.put("reloadTriggered", root.at("/collection/reloadTriggered").asBoolean(false));
        state.put("sessionId", root.at("/collection/sessionId").asText("unknown"));
        state.put("initialUrl", root.at("/collection/target/initialUrl").asText(""));
        state.put("finalUrl", root.at("/collection/target/finalUrl").asText(""));
        state.put("tabId", root.at("/page/tab/tabId").asInt(0));
        state.put("frameCount", root.at("/page/frames").size());
        state.put("artifactCount", root.at("/summary/artifactCount").asInt(0));
        state.put("chromiumOnlyArtifactCount", chromiumOnlyArtifactCount);
        state.put("chromiumOnlyCategories", chromiumOnlyCounts);
        state.put("storageKeyCount", countArtifacts(root.path("artifacts"), "storage-key"));
        state.put("indexedDbCount", countArtifacts(root.path("artifacts"), "indexeddb-database"));
        state.put("cacheStorageCount", countArtifacts(root.path("artifacts"), "cache"));
        state.put("serviceWorkerCount", countArtifacts(root.path("artifacts"), "service-worker"));
        state.put("workerCount", countArtifacts(root.path("artifacts"), "worker"));
        state.put("blobCount", countArtifacts(root.path("artifacts"), "blob"));
        state.put("dataUrlArtifactCount", countDataUrlArtifacts(root.path("artifacts")));
        state.put("runtimeIndicatorCount", countArtifacts(root.path("artifacts"), "runtime-indicator"));
        state.put("collectorSummary", buildCollectorSummary(root.path("collectors")));
        state.put("warningCount", root.at("/summary/warningCount").asInt(0));
        state.put("errorCount", root.at("/summary/errorCount").asInt(0));
        state.put("visibilityGapCount", root.at("/summary/visibilityGapCount").asInt(0));
        return state;
    }

    private static void appendFrameSummary(StringBuilder note, JsonNode frames) {
        int frameIndex = 0;
        for (JsonNode frame : frames) {
            if (frameIndex >= 5) {
                note.append("\n  - ... ").append(frames.size() - frameIndex).append(" more frame(s)");
                return;
            }

            note.append("\n  - frame ")
                .append(frame.path("frameId").asText("unknown"))
                .append(" parent=")
                .append(frame.path("parentFrameId").asText("top"))
                .append(" ")
                .append(frame.path("url").asText("unknown"));
            frameIndex++;
        }
    }

    private static String buildCollectorSummary(JsonNode collectors) {
        StringBuilder summary = new StringBuilder();
        for (JsonNode collector : collectors) {
            if (!summary.isEmpty()) {
                summary.append(", ");
            }
            summary.append(collector.path("collectorId").asText("unknown"))
                .append("=")
                .append(collector.path("status").asText("unknown"));
        }
        return summary.isEmpty() ? "none" : summary.toString();
    }

    private static int countArtifacts(JsonNode artifacts, String category) {
        int count = 0;
        for (JsonNode artifact : artifacts) {
            if (category.equals(artifact.path("category").asText(""))) {
                count++;
            }
        }
        return count;
    }

    private static int countDataUrlArtifacts(JsonNode artifacts) {
        int count = 0;
        for (JsonNode artifact : artifacts) {
            if (artifact.path("url").asText("").startsWith("data:")) {
                count++;
            }
        }
        return count;
    }

    private static String compactHeaderValue(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return "unknown";
        }
        return rawValue.replace('\r', ' ').replace('\n', ' ').replace(';', ',');
    }

    private static Annotations buildAnnotations(
        Annotations existing,
        String managedNote,
        boolean highlighted
    ) {
        String mergedNotes = upsertManagedNote(existing.hasNotes() ? existing.notes() : "", managedNote);
        Annotations annotations = Annotations.annotations(mergedNotes);
        if (existing.hasHighlightColor() && existing.highlightColor() != HighlightColor.NONE) {
            annotations = annotations.withHighlightColor(existing.highlightColor());
        }
        if (highlighted) {
            annotations = annotations.withHighlightColor(CHROMIUM_HIGHLIGHT);
        }
        return annotations;
    }

    private static String upsertManagedNote(String existingNotes, String managedNote) {
        String trimmedExisting = existingNotes == null ? "" : existingNotes.trim();
        if (trimmedExisting.isBlank()) {
            return managedNote;
        }

        int startIndex = trimmedExisting.indexOf(NOTE_START);
        if (startIndex < 0) {
            return trimmedExisting + "\n\n" + managedNote;
        }

        int endIndex = trimmedExisting.indexOf(NOTE_END, startIndex);
        if (endIndex < 0) {
            return trimmedExisting.substring(0, startIndex).trim() + "\n\n" + managedNote;
        }

        String prefix = trimmedExisting.substring(0, startIndex).trim();
        String suffix = trimmedExisting.substring(endIndex + NOTE_END.length()).trim();

        StringBuilder merged = new StringBuilder();
        if (!prefix.isBlank()) {
            merged.append(prefix).append("\n\n");
        }
        merged.append(managedNote);
        if (!suffix.isBlank()) {
            merged.append("\n\n").append(suffix);
        }
        return merged.toString();
    }

    private static Map<String, Integer> collectChromiumOnlyCounts(JsonNode artifacts) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (JsonNode artifact : artifacts) {
            if (!BlancheArtifactPairing.isChromiumOnly(artifact)) {
                continue;
            }

            String category = artifact.path("category").asText("unknown");
            counts.merge(category, 1, Integer::sum);
        }
        return counts;
    }

    private static String formatCounts(Map<String, Integer> counts) {
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

    private static String normalizeSiteMapUrl(String rawUrl) {
        if (rawUrl == null) {
            return "";
        }

        String trimmed = rawUrl.trim();
        if (trimmed.isBlank()) {
            return "";
        }

        try {
            URI uri = URI.create(trimmed);
            return new URI(
                uri.getScheme(),
                uri.getUserInfo(),
                uri.getHost(),
                uri.getPort(),
                uri.getPath(),
                uri.getQuery(),
                null
            ).toString();
        } catch (Exception exception) {
            int fragmentIndex = trimmed.indexOf('#');
            return fragmentIndex >= 0 ? trimmed.substring(0, fragmentIndex) : trimmed;
        }
    }

    public record IntegrationResult(
        String pageUrl,
        int chromiumOnlyArtifactCount,
        String chromiumOnlySummary,
        boolean highlighted,
        boolean syntheticEntry,
        int pairedEndpointCount,
        boolean sentToOrganizer,
        String statusMessage
    ) {}
}
