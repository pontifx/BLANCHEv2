package com.blanche.burp;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.util.Set;

/**
 * Shared rules for deciding which artifacts are Chromium-only (never visible as HTTP traffic)
 * and which host/endpoint they should be paired with in both the Burp site map and the BLANCHE
 * suite tab tree. Kept in one place so the two views never disagree about grouping.
 */
public final class BlancheArtifactPairing {
    public static final String SYNTHETIC_SEGMENT = "blanche-chromium-only";

    private static final Set<String> CHROMIUM_ONLY_CATEGORIES = Set.of(
        "blob",
        "data-url",
        "storage-key",
        "indexeddb-database",
        "cache",
        "service-worker",
        "runtime-indicator"
    );

    private BlancheArtifactPairing() {}

    public static boolean isChromiumOnly(JsonNode artifact) {
        String category = artifact.path("category").asText("unknown");
        if (CHROMIUM_ONLY_CATEGORIES.contains(category)) {
            return true;
        }

        String kind = artifact.path("kind").asText("");
        if (kind.startsWith("instrumented-")) {
            return true;
        }

        String url = artifact.path("url").asText("");
        if (url.startsWith("blob:") || url.startsWith("data:")) {
            return true;
        }

        for (JsonNode source : artifact.path("discoveredBy")) {
            if ("instrumentation".equals(source.asText(""))) {
                return true;
            }
        }

        return false;
    }

    /**
     * A stable grouping key for an artifact: a real URL when the artifact carries one that is
     * directly reachable over HTTP, otherwise a synthetic per-host/per-category bucket derived
     * from the page (or the blob's embedded origin) that produced it.
     */
    public static String pairingKey(JsonNode artifact, String pageUrl) {
        String artifactUrl = artifact.path("url").asText("");
        String category = artifact.path("category").asText("unknown");

        String httpUrl = extractHttpUrl(artifactUrl);
        if (httpUrl != null) {
            return normalizeUrl(httpUrl);
        }

        String origin = originForArtifact(artifactUrl, pageUrl);
        String bucket = origin.isBlank() ? SYNTHETIC_SEGMENT + "/" + category : origin + "/" + SYNTHETIC_SEGMENT + "/" + category;
        return bucket;
    }

    /** The hostname this artifact should be filed under, for tree/site-map grouping purposes. */
    public static String pairingHostname(JsonNode artifact, String pageUrl) {
        String artifactUrl = artifact.path("url").asText("");

        String httpUrl = extractHttpUrl(artifactUrl);
        if (httpUrl != null) {
            return hostnameOf(httpUrl);
        }

        String blobHost = blobEmbeddedHost(artifactUrl);
        if (!blobHost.isBlank()) {
            return blobHost;
        }

        return hostnameOf(pageUrl);
    }

    public static String hostnameOf(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return "";
        }

        try {
            URI uri = URI.create(rawUrl.trim());
            String host = uri.getHost();
            return host == null ? "" : host;
        } catch (Exception exception) {
            return "";
        }
    }

    public static String originOf(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return "";
        }

        try {
            URI uri = URI.create(rawUrl.trim());
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return "";
            }

            StringBuilder origin = new StringBuilder();
            origin.append(scheme).append("://").append(host);
            if (uri.getPort() != -1) {
                origin.append(':').append(uri.getPort());
            }
            return origin.toString();
        } catch (Exception exception) {
            return "";
        }
    }

    public static String normalizeUrl(String rawUrl) {
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

    private static String extractHttpUrl(String url) {
        if (url == null) {
            return null;
        }

        String trimmed = url.trim();
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return trimmed;
        }
        return null;
    }

    private static String blobEmbeddedHost(String url) {
        if (url == null || !url.startsWith("blob:")) {
            return "";
        }
        return hostnameOf(url.substring("blob:".length()));
    }

    private static String originForArtifact(String artifactUrl, String pageUrl) {
        if (artifactUrl != null && artifactUrl.startsWith("blob:")) {
            String remainder = artifactUrl.substring("blob:".length());
            String blobOrigin = originOf(remainder);
            if (!blobOrigin.isBlank()) {
                return blobOrigin;
            }
        }
        return originOf(pageUrl);
    }
}
