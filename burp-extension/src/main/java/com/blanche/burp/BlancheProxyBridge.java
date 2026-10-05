package com.blanche.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class BlancheProxyBridge implements ProxyRequestHandler, ProxyResponseHandler {
    public static final String INGEST_URL = "http://blanche.invalid/ingest";
    public static final String OSINT_SEED_URL = "http://blanche.invalid/osint/seed";
    public static final String OSINT_REPORT_URL = "http://blanche.invalid/osint/report";

    private static final String INGEST_HOST = "blanche.invalid";
    private static final String EXPORT_PATH = "/ingest";
    private static final String OSINT_SEED_PATH = "/osint/seed";
    private static final String OSINT_REPORT_PATH = "/osint/report";
    private static final String FORWARD_TARGET_URL = "http://burp/";

    private final MontoyaApi api;
    private final BlancheSuiteTab suiteTab;
    private final BlancheOsintCoordinator osintCoordinator;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ConcurrentMap<Integer, PendingResponsePlan> pendingResponses = new ConcurrentHashMap<>();
    private final Registration requestRegistration;
    private final Registration responseRegistration;

    private BlancheProxyBridge(
        MontoyaApi api,
        BlancheSuiteTab suiteTab,
        BlancheOsintCoordinator osintCoordinator
    ) {
        this.api = api;
        this.suiteTab = suiteTab;
        this.osintCoordinator = osintCoordinator;
        this.requestRegistration = api.proxy().registerRequestHandler(this);
        this.responseRegistration = api.proxy().registerResponseHandler(this);
    }

    public static BlancheProxyBridge start(
        MontoyaApi api,
        BlancheSuiteTab suiteTab,
        BlancheOsintCoordinator osintCoordinator
    ) {
        return new BlancheProxyBridge(api, suiteTab, osintCoordinator);
    }

    public String endpoint() {
        return INGEST_URL;
    }

    public String osintSeedEndpoint() {
        return OSINT_SEED_URL;
    }

    public String osintReportEndpoint() {
        return OSINT_REPORT_URL;
    }

    public void stop() {
        if (requestRegistration.isRegistered()) {
            requestRegistration.deregister();
        }
        if (responseRegistration.isRegistered()) {
            responseRegistration.deregister();
        }
        pendingResponses.clear();
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        RequestRoute route = routeFor(request);
        if (route == null) {
            return ProxyRequestReceivedAction.doNotIntercept(request);
        }

        pendingResponses.put(request.messageId(), buildResponsePlan(request, route));
        HttpRequest transitRequest = HttpRequest.httpRequestFromUrl(FORWARD_TARGET_URL);
        return ProxyRequestReceivedAction.doNotIntercept(transitRequest, request.annotations());
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        return ProxyResponseReceivedAction.doNotIntercept(response, response.annotations());
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        PendingResponsePlan plan = pendingResponses.remove(response.messageId());
        if (plan == null) {
            return ProxyResponseToBeSentAction.continueWith(response, response.annotations());
        }

        return ProxyResponseToBeSentAction.continueWith(plan.response(), response.annotations());
    }

    private PendingResponsePlan buildResponsePlan(InterceptedRequest request, RequestRoute route) {
        String method = request.method().toUpperCase();
        if ("OPTIONS".equals(method)) {
            return new PendingResponsePlan(buildEmptyResponse(204, "No Content"));
        }

        if (!"POST".equals(method)) {
            return new PendingResponsePlan(
                buildJsonResponse(
                    405,
                    "Method Not Allowed",
                    Map.of(
                        "status",
                        "error",
                        "message",
                        "Only POST and OPTIONS are supported."
                    )
                )
            );
        }

        try {
            String rawJson = request.bodyToString();
            return switch (route) {
                case BROWSER_EXPORT -> handleBrowserExport(rawJson);
                case OSINT_SEED -> handleOsintSeed(rawJson);
                case OSINT_REPORT -> handleOsintReport(rawJson);
            };
        } catch (IOException exception) {
            api.logging().logToError("BLANCHE rejected ingest payload: " + exception.getMessage());
            return new PendingResponsePlan(
                buildJsonResponse(
                    400,
                    "Bad Request",
                    Map.of(
                        "status",
                        "error",
                        "message",
                        exception.getMessage()
                    )
                )
            );
        } catch (RuntimeException exception) {
            api.logging().logToError("BLANCHE ingest failed: " + exception.getMessage());
            return new PendingResponsePlan(
                buildJsonResponse(
                    500,
                    "Internal Server Error",
                    Map.of(
                        "status",
                        "error",
                        "message",
                        exception.getMessage()
                    )
                )
            );
        }
    }

    private PendingResponsePlan handleBrowserExport(String rawJson) throws IOException {
        BlancheSuiteTab.IngestionResult result = suiteTab.ingestBrowserExport(
            rawJson,
            "Automatic Chromium handoff via Burp proxy"
        );

        api.logging().logToOutput(
            "BLANCHE auto-ingested "
                + (result.pageUrl().isBlank() ? "(unknown page)" : result.pageUrl())
                + " with "
                + result.chromiumOnlyArtifactCount()
                + " Chromium-only artifacts via proxy bridge."
        );

        return new PendingResponsePlan(buildEmptyResponse(204, "No Content"));
    }

    private PendingResponsePlan handleOsintSeed(String rawJson) throws IOException {
        BlancheSuiteTab.OsintSeedResult result = osintCoordinator.ingestSeed(
            rawJson,
            "Automatic Chromium OSINT seed via Burp proxy"
        );
        api.logging().logToOutput(
            "BLANCHE ingested OSINT seed for "
                + (result.primaryHostname().isBlank() ? "(unknown host)" : result.primaryHostname())
                + " with "
                + result.relatedHostCount()
                + " related hosts via proxy bridge."
        );

        return new PendingResponsePlan(buildEmptyResponse(202, "Accepted"));
    }

    private PendingResponsePlan handleOsintReport(String rawJson) throws IOException {
        BlancheSuiteTab.OsintReportResult result = suiteTab.ingestOsintReport(
            rawJson,
            "Automatic OSINT report handoff via Burp proxy"
        );
        api.logging().logToOutput(
            "BLANCHE ingested OSINT report for "
                + (result.primaryHostname().isBlank() ? "(unknown host)" : result.primaryHostname())
                + " with "
                + result.findingCount()
                + " findings via proxy bridge."
        );

        return new PendingResponsePlan(buildEmptyResponse(202, "Accepted"));
    }

    private HttpResponse buildEmptyResponse(int statusCode, String reasonPhrase) {
        return HttpResponse.httpResponse(
            "HTTP/1.1 "
                + statusCode
                + " "
                + reasonPhrase
                + "\r\n"
                + "Access-Control-Allow-Origin: *\r\n"
                + "Access-Control-Allow-Headers: Content-Type\r\n"
                + "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                + "Cache-Control: no-store\r\n"
                + "Content-Length: 0\r\n"
                + "\r\n"
        );
    }

    private HttpResponse buildJsonResponse(int statusCode, String reasonPhrase, Map<String, ?> payload) {
        try {
            byte[] body = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(
                new LinkedHashMap<>(payload)
            );
            return HttpResponse.httpResponse(
                "HTTP/1.1 "
                    + statusCode
                    + " "
                    + reasonPhrase
                    + "\r\n"
                    + "Access-Control-Allow-Origin: *\r\n"
                    + "Access-Control-Allow-Headers: Content-Type\r\n"
                    + "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "Content-Type: application/json; charset=utf-8\r\n"
                    + "Content-Length: "
                    + body.length
                    + "\r\n"
                    + "\r\n"
                    + new String(body, StandardCharsets.UTF_8)
            );
        } catch (IOException exception) {
            return HttpResponse.httpResponse(
                "HTTP/1.1 500 Internal Server Error\r\n"
                    + "Access-Control-Allow-Origin: *\r\n"
                    + "Access-Control-Allow-Headers: Content-Type\r\n"
                    + "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "Content-Length: 0\r\n"
                    + "\r\n"
            );
        }
    }

    private static RequestRoute routeFor(InterceptedRequest request) {
        try {
            URI uri = URI.create(request.url());
            String host = uri.getHost();
            String path = uri.getPath();
            if (!INGEST_HOST.equalsIgnoreCase(host)) {
                return null;
            }

            if (EXPORT_PATH.equals(path)) {
                return RequestRoute.BROWSER_EXPORT;
            }
            if (OSINT_SEED_PATH.equals(path)) {
                return RequestRoute.OSINT_SEED;
            }
            if (OSINT_REPORT_PATH.equals(path)) {
                return RequestRoute.OSINT_REPORT;
            }
            return null;
        } catch (Exception exception) {
            return null;
        }
    }

    private enum RequestRoute {
        BROWSER_EXPORT,
        OSINT_SEED,
        OSINT_REPORT
    }

    private record PendingResponsePlan(HttpResponse response) {}
}
