package com.blanche.burp;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Tolerant, presentation-oriented adapter for an optional traffic ledger embedded in a browser
 * export. Parsing never rejects an otherwise usable legacy export.
 */
public final class BlancheTrafficLedger {
    private BlancheTrafficLedger() {}

    public static LedgerView parse(JsonNode exportRoot) {
        JsonNode ledger = exportRoot == null ? null : exportRoot.get("trafficLedger");
        if (ledger == null || ledger.isMissingNode() || ledger.isNull()) {
            return LedgerView.absent();
        }

        List<String> warnings = new ArrayList<>();
        if (!ledger.isObject()) {
            warnings.add("trafficLedger was present but was not a JSON object.");
            return new LedgerView(
                true,
                "unknown",
                "unknown",
                "",
                "",
                "",
                "",
                "",
                List.of(),
                List.copyOf(warnings)
            );
        }

        JsonNode captureCoverage = ledger.at("/metadata/captureCoverage");
        if (captureCoverage.isObject() && captureCoverage.path("truncated").asBoolean(false)) {
            warnings.add(
                "Traffic ledger is a retained subset: exported "
                    + captureCoverage.path("exportedEntryCount").asInt(0)
                    + " of "
                    + captureCoverage.path("availableEntryCount").asInt(0)
                    + " available entries; "
                    + captureCoverage.path("droppedEntryCount").asInt(0)
                    + " store-wide entries were dropped by prior retention limits (conservative attribution)."
            );
        }
        for (String reasonCode : stringValues(captureCoverage, "/reasonCodes")) {
            warnings.add("Traffic ledger coverage: " + reasonCode);
        }

        JsonNode entriesNode = firstNode(ledger, "/entries", "/rows", "/observations");
        List<EntryView> entries = new ArrayList<>();
        if (entriesNode == null) {
            warnings.add("trafficLedger did not contain an entries array.");
        } else if (!entriesNode.isArray()) {
            warnings.add("trafficLedger.entries was not an array.");
        } else {
            int index = 0;
            for (JsonNode entry : entriesNode) {
                if (!entry.isObject()) {
                    warnings.add("Ignored non-object traffic ledger entry at index " + index + ".");
                } else {
                    entries.add(parseEntry(entry, index, warnings));
                }
                index++;
            }
        }

        entries.sort(BlancheTrafficLedger::compareEntries);
        return new LedgerView(
            true,
            text(ledger, "/kind"),
            text(ledger, "/schemaVersion"),
            firstText(ledger, "/metadata/ledgerId", "/metadata/id", "/ledgerId"),
            firstText(ledger, "/metadata/generatedAt", "/metadata/createdAt", "/generatedAt"),
            firstText(ledger, "/scopePolicy/policyId", "/scopePolicy/id"),
            firstText(ledger, "/scopePolicy/policyVersion", "/scopePolicy/version"),
            firstText(ledger, "/metadata/scoreModel", "/scoreModel"),
            List.copyOf(entries),
            List.copyOf(warnings)
        );
    }

    public static String render(LedgerView ledger) {
        if (!ledger.present()) {
            return String.join(
                "\n",
                "No traffic ledger was included in this export.",
                "Legacy BLANCHE exports remain supported; collect a score-aware export to populate this view."
            );
        }

        StringBuilder output = new StringBuilder();
        output.append("Traffic Priority Ledger\n");
        output.append("Scores rank traffic for operator review; they are not vulnerability severity or proof of impact.\n\n");
        output.append("Kind: ").append(orUnknown(ledger.kind())).append('\n');
        output.append("Schema: ").append(orUnknown(ledger.schemaVersion())).append('\n');
        if (!ledger.ledgerId().isBlank()) {
            output.append("Ledger ID: ").append(ledger.ledgerId()).append('\n');
        }
        if (!ledger.generatedAt().isBlank()) {
            output.append("Generated: ").append(ledger.generatedAt()).append('\n');
        }
        if (!ledger.policyId().isBlank() || !ledger.policyVersion().isBlank()) {
            output.append("Scope policy: ")
                .append(ledger.policyId().isBlank() ? "unknown" : ledger.policyId());
            if (!ledger.policyVersion().isBlank()) {
                output.append(" @ ").append(ledger.policyVersion());
            }
            output.append('\n');
        }
        if (!ledger.scoreModel().isBlank()) {
            output.append("Score model: ").append(ledger.scoreModel()).append('\n');
        }
        output.append("Entries: ").append(ledger.entryCount()).append('\n');
        output.append("Scored entries: ").append(ledger.scoredEntryCount()).append('\n');
        output.append("Highest traffic priority: ").append(ledger.highestPriorityLabel()).append('\n');

        if (!ledger.warnings().isEmpty()) {
            output.append("\nParser notes\n");
            for (String warning : ledger.warnings()) {
                output.append("- ").append(warning).append('\n');
            }
        }

        if (ledger.entries().isEmpty()) {
            output.append("\nNo traffic ledger entries were present.\n");
            return output.toString();
        }

        output.append("\nEntries (traffic priority descending)\n");
        for (EntryView entry : ledger.entries()) {
            output.append("\n[").append(entry.priorityLabel()).append("] ")
                .append(orUnknown(entry.scopeDisposition()))
                .append(" | ")
                .append(orUnknown(entry.method()))
                .append(" | ")
                .append(orUnknown(entry.canonicalEndpoint()))
                .append('\n');
            if (!entry.entryId().isBlank()) {
                output.append("  entry: ").append(entry.entryId()).append('\n');
            }
            output.append("  roles: ").append(joinOrNone(entry.roles())).append('\n');
            if (!entry.boundary().isBlank()) {
                output.append("  boundary: ").append(entry.boundary()).append('\n');
            }
            output.append("  status/count: ")
                .append(joinOrNone(entry.statusCodes()))
                .append(" / ")
                .append(entry.count() == null ? "unknown" : entry.count())
                .append('\n');
            if (!entry.firstSeen().isBlank() || !entry.lastSeen().isBlank()) {
                output.append("  observed: ")
                    .append(entry.firstSeen().isBlank() ? "unknown" : entry.firstSeen())
                    .append(" -> ")
                    .append(entry.lastSeen().isBlank() ? "unknown" : entry.lastSeen())
                    .append('\n');
            }
            if (!entry.resourceTypes().isEmpty() || !entry.contentTypes().isEmpty()) {
                output.append("  traffic: resources=")
                    .append(joinOrNone(entry.resourceTypes()))
                    .append("; content-types=")
                    .append(joinOrNone(entry.contentTypes()))
                    .append('\n');
            }
            output.append("  factors: ").append(joinOrNone(entry.factors())).append('\n');
            output.append("  reasons: ").append(joinOrNone(entry.reasonCodes())).append('\n');
            output.append("  provenance: ").append(joinOrNone(entry.provenance())).append('\n');
        }

        return output.toString();
    }

    private static EntryView parseEntry(JsonNode entry, int index, List<String> warnings) {
        String entryId = firstText(entry, "/entryId", "/observationId", "/rowId", "/id");
        String entryLabel = entryId.isBlank() ? "entry " + index : entryId;
        Double score = optionalDouble(
            entry,
            entryLabel,
            warnings,
            "/priority/score",
            "/score",
            "/priorityScore",
            "/priority/value"
        );

        List<String> reasons = distinctStrings(
            stringValues(entry, "/scope/reasonCodes"),
            stringValues(entry, "/classification/reasonCodes")
        );
        String basis = firstText(entry, "/scope/basis", "/scope/reason");
        if (!basis.isBlank()) {
            reasons = append(reasons, "scope-basis=" + basis);
        }
        String scopeConfidence = text(entry, "/scope/confidence");
        if (!scopeConfidence.isBlank()) {
            reasons = append(reasons, "scope-confidence=" + scopeConfidence);
        }
        for (String ruleId : stringValues(entry, "/scope/matchedRuleIds")) {
            reasons = append(reasons, "scope-rule=" + ruleId);
        }

        List<String> provenance = new ArrayList<>();
        appendPrefixed(provenance, "source=", stringValues(entry, "/observation/sources"));
        appendPrefixed(provenance, "origin=", stringValues(entry, "/observation/sourceOrigins"));
        provenance.addAll(formatEvidence(firstNode(entry, "/evidence", "/provenance")));

        return new EntryView(
            entryId,
            firstText(entry, "/endpoint/method", "/method").toUpperCase(Locale.ROOT),
            canonicalEndpoint(entry),
            firstText(entry, "/scope/disposition", "/scope/status", "/scopeDisposition"),
            firstText(entry, "/classification/boundary", "/boundary"),
            stringValues(entry, "/classification/roles", "/roles"),
            score,
            firstText(entry, "/priority/band", "/scoreBand", "/band"),
            optionalLong(entry, "/observation/count", "/count", "/occurrenceCount"),
            stringValues(entry, "/observation/statusCodes", "/statusCodes", "/status"),
            stringValues(entry, "/observation/resourceTypes", "/resourceTypes"),
            stringValues(entry, "/observation/contentTypes", "/contentTypes"),
            firstText(entry, "/observation/firstSeen", "/firstSeen"),
            firstText(entry, "/observation/lastSeen", "/lastSeen", "/observedAt"),
            formatFactors(firstNode(entry, "/priority/factors", "/factors")),
            List.copyOf(reasons),
            List.copyOf(new LinkedHashSet<>(provenance))
        );
    }

    private static int compareEntries(EntryView left, EntryView right) {
        if (left.score() == null && right.score() != null) {
            return 1;
        }
        if (left.score() != null && right.score() == null) {
            return -1;
        }
        if (left.score() != null) {
            int scoreComparison = Double.compare(right.score(), left.score());
            if (scoreComparison != 0) {
                return scoreComparison;
            }
        }

        int endpointComparison = left.canonicalEndpoint().compareToIgnoreCase(right.canonicalEndpoint());
        if (endpointComparison != 0) {
            return endpointComparison;
        }
        return left.entryId().compareToIgnoreCase(right.entryId());
    }

    private static String canonicalEndpoint(JsonNode entry) {
        String explicit = firstText(
            entry,
            "/endpoint/canonicalEndpoint",
            "/endpoint/canonical",
            "/canonicalEndpoint",
            "/endpoint/url",
            "/url"
        );
        if (!explicit.isBlank()) {
            return explicit;
        }

        String scheme = text(entry, "/endpoint/scheme");
        String host = text(entry, "/endpoint/host");
        String port = text(entry, "/endpoint/port");
        String path = text(entry, "/endpoint/pathTemplate");
        List<String> queryNames = stringValues(entry, "/endpoint/queryParameterNames");

        StringBuilder endpoint = new StringBuilder();
        if (!scheme.isBlank()) {
            endpoint.append(scheme).append("://");
        }
        endpoint.append(host);
        if (!port.isBlank() && !isDefaultPort(scheme, port)) {
            endpoint.append(':').append(port);
        }
        if (!path.isBlank()) {
            if (!host.isBlank() && !path.startsWith("/")) {
                endpoint.append('/');
            }
            endpoint.append(path);
        } else if (!host.isBlank()) {
            endpoint.append('/');
        }
        if (!queryNames.isEmpty()) {
            endpoint.append('?').append(String.join("&", queryNames));
        }
        return endpoint.toString();
    }

    private static boolean isDefaultPort(String scheme, String port) {
        return ("http".equalsIgnoreCase(scheme) && "80".equals(port))
            || ("https".equalsIgnoreCase(scheme) && "443".equals(port));
    }

    private static Double optionalDouble(
        JsonNode root,
        String entryLabel,
        List<String> warnings,
        String... pointers
    ) {
        JsonNode value = firstNode(root, pointers);
        if (value == null) {
            return null;
        }

        double parsed;
        if (value.isNumber()) {
            parsed = value.asDouble();
        } else if (value.isTextual()) {
            try {
                parsed = Double.parseDouble(value.asText().trim());
            } catch (NumberFormatException exception) {
                warnings.add("Ignored non-numeric traffic priority score for " + entryLabel + ".");
                return null;
            }
        } else {
            warnings.add("Ignored non-numeric traffic priority score for " + entryLabel + ".");
            return null;
        }

        if (!Double.isFinite(parsed) || parsed < 0 || parsed > 100) {
            warnings.add("Ignored out-of-range traffic priority score for " + entryLabel + ".");
            return null;
        }
        return parsed;
    }

    private static Long optionalLong(JsonNode root, String... pointers) {
        JsonNode value = firstNode(root, pointers);
        if (value == null) {
            return null;
        }
        if (value.canConvertToLong()) {
            long parsed = value.asLong();
            return parsed >= 0 ? parsed : null;
        }
        if (value.isTextual()) {
            try {
                long parsed = Long.parseLong(value.asText().trim());
                return parsed >= 0 ? parsed : null;
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static List<String> formatFactors(JsonNode factors) {
        if (factors == null) {
            return List.of();
        }
        if (!factors.isArray()) {
            return List.of(compact(factors));
        }

        List<String> output = new ArrayList<>();
        for (JsonNode factor : factors) {
            if (!factor.isObject()) {
                String value = scalarText(factor);
                if (!value.isBlank()) {
                    output.add(value);
                }
                continue;
            }

            String code = firstText(factor, "/code", "/id", "/name");
            JsonNode deltaNode = firstNode(factor, "/delta", "/weight", "/score");
            String reason = firstText(factor, "/reason", "/description");
            List<String> evidenceRefs = stringValues(factor, "/evidenceRefs", "/evidenceReferences");
            StringBuilder formatted = new StringBuilder(code.isBlank() ? "factor" : code);
            if (deltaNode != null && deltaNode.isNumber()) {
                double delta = deltaNode.asDouble();
                formatted.append(" (").append(delta >= 0 ? "+" : "").append(formatNumber(delta)).append(')');
            }
            if (!reason.isBlank()) {
                formatted.append(": ").append(reason);
            }
            if (!evidenceRefs.isEmpty()) {
                formatted.append(" [evidence=").append(String.join(", ", evidenceRefs)).append(']');
            }
            output.add(formatted.toString());
        }
        return List.copyOf(output);
    }

    private static List<String> formatEvidence(JsonNode evidence) {
        if (evidence == null) {
            return List.of();
        }
        if (!evidence.isArray()) {
            return List.of(compact(evidence));
        }

        List<String> output = new ArrayList<>();
        for (JsonNode item : evidence) {
            if (!item.isObject()) {
                String value = scalarText(item);
                if (!value.isBlank()) {
                    output.add(value);
                }
                continue;
            }

            String kind = text(item, "/kind");
            String id = text(item, "/id");
            String source = text(item, "/source");
            String observedAt = text(item, "/observedAt");
            StringBuilder formatted = new StringBuilder();
            if (!kind.isBlank()) {
                formatted.append(kind);
            }
            if (!id.isBlank()) {
                if (!formatted.isEmpty()) {
                    formatted.append(':');
                }
                formatted.append(id);
            }
            if (!source.isBlank()) {
                if (!formatted.isEmpty()) {
                    formatted.append(" via ");
                }
                formatted.append(source);
            }
            if (!observedAt.isBlank()) {
                if (!formatted.isEmpty()) {
                    formatted.append(" @ ");
                }
                formatted.append(observedAt);
            }
            output.add(formatted.isEmpty() ? compact(item) : formatted.toString());
        }
        return List.copyOf(output);
    }

    private static List<String> stringValues(JsonNode root, String... pointers) {
        JsonNode value = firstNode(root, pointers);
        if (value == null) {
            return List.of();
        }
        if (!value.isArray()) {
            String text = scalarText(value);
            return text.isBlank() ? List.of() : List.of(text);
        }

        Set<String> output = new LinkedHashSet<>();
        for (JsonNode item : value) {
            String text = scalarText(item);
            if (!text.isBlank()) {
                output.add(text);
            }
        }
        return List.copyOf(output);
    }

    private static String scalarText(JsonNode value) {
        if (value == null || value.isMissingNode() || value.isNull()) {
            return "";
        }
        if (value.isValueNode()) {
            return value.asText("").trim();
        }
        return compact(value);
    }

    private static String compact(JsonNode value) {
        return value == null ? "" : value.toString().replace('\n', ' ').replace('\r', ' ');
    }

    private static String text(JsonNode root, String pointer) {
        JsonNode value = firstNode(root, pointer);
        return value == null ? "" : scalarText(value);
    }

    private static String firstText(JsonNode root, String... pointers) {
        for (String pointer : pointers) {
            String value = text(root, pointer);
            if (!value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private static JsonNode firstNode(JsonNode root, String... pointers) {
        if (root == null) {
            return null;
        }
        for (String pointer : pointers) {
            JsonNode value = pointer.startsWith("/") ? root.at(pointer) : root.get(pointer);
            if (value != null && !value.isMissingNode() && !value.isNull()) {
                return value;
            }
        }
        return null;
    }

    @SafeVarargs
    private static List<String> distinctStrings(List<String>... sources) {
        Set<String> output = new LinkedHashSet<>();
        for (List<String> source : sources) {
            output.addAll(source);
        }
        return List.copyOf(output);
    }

    private static List<String> append(List<String> source, String value) {
        List<String> output = new ArrayList<>(source);
        output.add(value);
        return List.copyOf(output);
    }

    private static void appendPrefixed(List<String> target, String prefix, List<String> values) {
        for (String value : values) {
            target.add(prefix + value);
        }
    }

    private static String joinOrNone(List<String> values) {
        return values.isEmpty() ? "none" : String.join(", ", values);
    }

    private static String orUnknown(String value) {
        return value == null || value.isBlank() ? "unknown" : value;
    }

    private static String formatNumber(double value) {
        return value == Math.rint(value) ? Long.toString(Math.round(value)) : String.format(Locale.ROOT, "%.2f", value);
    }

    public record LedgerView(
        boolean present,
        String kind,
        String schemaVersion,
        String ledgerId,
        String generatedAt,
        String policyId,
        String policyVersion,
        String scoreModel,
        List<EntryView> entries,
        List<String> warnings
    ) {
        static LedgerView absent() {
            return new LedgerView(false, "", "", "", "", "", "", "", List.of(), List.of());
        }

        public int entryCount() {
            return entries.size();
        }

        public long scoredEntryCount() {
            return entries.stream().filter(entry -> entry.score() != null).count();
        }

        public EntryView highestPriorityEntry() {
            return entries.stream().filter(entry -> entry.score() != null).findFirst().orElse(null);
        }

        public String highestPriorityLabel() {
            EntryView highest = highestPriorityEntry();
            return highest == null ? "unscored" : highest.priorityLabel();
        }
    }

    public record EntryView(
        String entryId,
        String method,
        String canonicalEndpoint,
        String scopeDisposition,
        String boundary,
        List<String> roles,
        Double score,
        String band,
        Long count,
        List<String> statusCodes,
        List<String> resourceTypes,
        List<String> contentTypes,
        String firstSeen,
        String lastSeen,
        List<String> factors,
        List<String> reasonCodes,
        List<String> provenance
    ) {
        public String priorityLabel() {
            if (score == null) {
                return band.isBlank() ? "unscored" : "unscored / " + band;
            }
            String label = formatNumber(score);
            return band.isBlank() ? label : label + " / " + band;
        }
    }
}
