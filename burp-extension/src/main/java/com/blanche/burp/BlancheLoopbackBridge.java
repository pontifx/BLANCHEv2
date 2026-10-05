package com.blanche.burp;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class BlancheLoopbackBridge {
    public static final String DEFAULT_HOST = "127.0.0.1";
    public static final int DEFAULT_PORT = 47625;
    public static final String EXPORT_PATH = "/api/blanche/ingest";
    public static final String OSINT_SEED_PATH = "/api/blanche/osint/seed";
    public static final String OSINT_REPORT_PATH = "/api/blanche/osint/report";

    private static final int SOCKET_TIMEOUT_MS = 5000;
    private static final int MAX_LINE_LENGTH = 16 * 1024;

    private final MontoyaApi api;
    private final BlancheSuiteTab suiteTab;
    private final BlancheOsintCoordinator osintCoordinator;
    private final ServerSocket serverSocket;
    private final ExecutorService workerPool;
    private final Thread acceptThread;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AtomicBoolean running = new AtomicBoolean(true);

    private BlancheLoopbackBridge(
        MontoyaApi api,
        BlancheSuiteTab suiteTab,
        BlancheOsintCoordinator osintCoordinator,
        ServerSocket serverSocket,
        ExecutorService workerPool
    ) {
        this.api = api;
        this.suiteTab = suiteTab;
        this.osintCoordinator = osintCoordinator;
        this.serverSocket = serverSocket;
        this.workerPool = workerPool;
        this.acceptThread = new Thread(this::acceptLoop, "blanche-loopback-listener");
        this.acceptThread.setDaemon(true);
    }

    public static BlancheLoopbackBridge start(
        MontoyaApi api,
        BlancheSuiteTab suiteTab,
        BlancheOsintCoordinator osintCoordinator
    ) throws IOException {
        ServerSocket serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(InetAddress.getByName(DEFAULT_HOST), DEFAULT_PORT));
        ExecutorService workerPool = Executors.newCachedThreadPool((runnable) -> {
            Thread thread = new Thread(runnable, "blanche-loopback-worker");
            thread.setDaemon(true);
            return thread;
        });

        BlancheLoopbackBridge bridge = new BlancheLoopbackBridge(
            api,
            suiteTab,
            osintCoordinator,
            serverSocket,
            workerPool
        );
        bridge.acceptThread.start();
        return bridge;
    }

    public String endpoint() {
        return "http://" + DEFAULT_HOST + ":" + serverSocket.getLocalPort() + EXPORT_PATH;
    }

    public String osintSeedEndpoint() {
        return "http://" + DEFAULT_HOST + ":" + serverSocket.getLocalPort() + OSINT_SEED_PATH;
    }

    public String osintReportEndpoint() {
        return "http://" + DEFAULT_HOST + ":" + serverSocket.getLocalPort() + OSINT_REPORT_PATH;
    }

    public void stop() {
        if (!running.getAndSet(false)) {
            return;
        }

        try {
            serverSocket.close();
        } catch (IOException ignored) {
        }

        workerPool.shutdownNow();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket socket = serverSocket.accept();
                workerPool.execute(() -> handleClient(socket));
            } catch (SocketException exception) {
                if (running.get()) {
                    api.logging().logToError("BLANCHE loopback accept loop failed: " + exception.getMessage());
                }
                break;
            } catch (RuntimeException exception) {
                if (running.get()) {
                    api.logging().logToError("BLANCHE loopback worker scheduling failed: " + exception.getMessage());
                }
            } catch (IOException exception) {
                if (running.get()) {
                    api.logging().logToError("BLANCHE loopback accept loop failed: " + exception.getMessage());
                }
            }
        }
    }

    private void handleClient(Socket socket) {
        try (socket) {
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();

            HttpRequestData request;
            try {
                request = readRequest(input);
            } catch (IOException exception) {
                writeJsonResponse(
                    output,
                    400,
                    Map.of(
                        "status",
                        "error",
                        "message",
                        exception.getMessage()
                    )
                );
                return;
            }

            handleRequest(output, request);
        } catch (SocketException exception) {
            if (running.get()) {
                api.logging().logToError("BLANCHE loopback socket failure: " + exception.getMessage());
            }
        } catch (IOException exception) {
            if (running.get()) {
                api.logging().logToError("BLANCHE loopback I/O failure: " + exception.getMessage());
            }
        } catch (RuntimeException exception) {
            if (running.get()) {
                api.logging().logToError("BLANCHE loopback runtime failure: " + exception.getMessage());
            }
        }
    }

    private void handleRequest(OutputStream output, HttpRequestData request) throws IOException {
        RequestRoute route = routeFor(request.path());
        if (route == null) {
            writeJsonResponse(
                output,
                404,
                Map.of(
                    "status",
                    "error",
                    "message",
                    "Unknown path."
                )
            );
            return;
        }

        if ("OPTIONS".equals(request.method())) {
            writeEmptyResponse(output, route == RequestRoute.BROWSER_EXPORT ? 204 : 202);
            return;
        }

        if (!"POST".equals(request.method())) {
            Map<String, String> headers = corsHeaders();
            headers.put("Allow", "POST, OPTIONS");
            writeJsonResponse(
                output,
                405,
                headers,
                Map.of(
                    "status",
                    "error",
                    "message",
                    "Only POST and OPTIONS are supported."
                )
            );
            return;
        }

        try {
            String rawJson = new String(request.body(), StandardCharsets.UTF_8);
            switch (route) {
                case BROWSER_EXPORT -> handleBrowserExport(output, rawJson);
                case OSINT_SEED -> handleOsintSeed(output, rawJson);
                case OSINT_REPORT -> handleOsintReport(output, rawJson);
            }
        } catch (IOException exception) {
            api.logging().logToError("BLANCHE loopback rejected ingest payload: " + exception.getMessage());
            writeJsonResponse(
                output,
                400,
                Map.of(
                    "status",
                    "error",
                    "message",
                    exception.getMessage()
                )
            );
        } catch (RuntimeException exception) {
            api.logging().logToError("BLANCHE loopback ingest failed: " + exception.getMessage());
            writeJsonResponse(
                output,
                500,
                Map.of(
                    "status",
                    "error",
                    "message",
                    exception.getMessage()
                )
            );
        }
    }

    private void handleBrowserExport(OutputStream output, String rawJson) throws IOException {
        BlancheSuiteTab.IngestionResult result = suiteTab.ingestBrowserExport(
            rawJson,
            "Automatic Chromium handoff via loopback"
        );

        api.logging().logToOutput(
            "BLANCHE auto-ingested "
                + (result.pageUrl().isBlank() ? "(unknown page)" : result.pageUrl())
                + " with "
                + result.chromiumOnlyArtifactCount()
                + " Chromium-only artifacts via loopback."
        );

        writeJsonResponse(
            output,
            200,
            Map.of(
                "status",
                "ok",
                "pageUrl",
                result.pageUrl(),
                "artifactCount",
                result.artifactCount(),
                "chromiumOnlyArtifactCount",
                result.chromiumOnlyArtifactCount(),
                "highlightedInSiteMap",
                result.highlightedInSiteMap(),
                "siteMapStatus",
                result.siteMapStatus()
            )
        );
    }

    private void handleOsintSeed(OutputStream output, String rawJson) throws IOException {
        BlancheSuiteTab.OsintSeedResult result = osintCoordinator.ingestSeed(
            rawJson,
            "Automatic Chromium OSINT seed via loopback"
        );
        api.logging().logToOutput(
            "BLANCHE ingested OSINT seed for "
                + (result.primaryHostname().isBlank() ? "(unknown host)" : result.primaryHostname())
                + " via loopback."
        );

        writeJsonResponse(
            output,
            202,
            Map.of(
                "status",
                "accepted",
                "primaryHostname",
                result.primaryHostname(),
                "relatedHostCount",
                result.relatedHostCount()
            )
        );
    }

    private void handleOsintReport(OutputStream output, String rawJson) throws IOException {
        BlancheSuiteTab.OsintReportResult result = suiteTab.ingestOsintReport(
            rawJson,
            "Automatic OSINT report handoff via loopback"
        );
        api.logging().logToOutput(
            "BLANCHE ingested OSINT report for "
                + (result.primaryHostname().isBlank() ? "(unknown host)" : result.primaryHostname())
                + " via loopback."
        );

        writeJsonResponse(
            output,
            202,
            Map.of(
                "status",
                "accepted",
                "primaryHostname",
                result.primaryHostname(),
                "findingCount",
                result.findingCount()
            )
        );
    }

    private HttpRequestData readRequest(InputStream input) throws IOException {
        String requestLine = readAsciiLine(input);
        if (requestLine == null || requestLine.isBlank()) {
            throw new EOFException("Empty HTTP request.");
        }

        String[] requestParts = requestLine.split(" ", 3);
        if (requestParts.length < 2) {
            throw new IOException("Malformed HTTP request line.");
        }

        Map<String, String> headers = new LinkedHashMap<>();
        while (true) {
            String line = readAsciiLine(input);
            if (line == null) {
                throw new EOFException("Unexpected end of headers.");
            }
            if (line.isEmpty()) {
                break;
            }

            int separator = line.indexOf(':');
            if (separator <= 0) {
                continue;
            }

            String name = line.substring(0, separator).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(separator + 1).trim();
            headers.put(name, value);
        }

        int contentLength = parseContentLength(headers.get("content-length"));
        byte[] body = readBody(input, contentLength);
        return new HttpRequestData(
            requestParts[0].trim().toUpperCase(Locale.ROOT),
            extractPath(requestParts[1].trim()),
            body
        );
    }

    private static int parseContentLength(String rawLength) throws IOException {
        if (rawLength == null || rawLength.isBlank()) {
            return 0;
        }

        try {
            int parsed = Integer.parseInt(rawLength.trim());
            if (parsed < 0) {
                throw new IOException("Negative Content-Length is not supported.");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IOException("Invalid Content-Length header.");
        }
    }

    private static byte[] readBody(InputStream input, int contentLength) throws IOException {
        byte[] body = new byte[contentLength];
        int offset = 0;
        while (offset < contentLength) {
            int read = input.read(body, offset, contentLength - offset);
            if (read < 0) {
                throw new EOFException("Unexpected end of request body.");
            }
            offset += read;
        }
        return body;
    }

    private static String extractPath(String target) {
        try {
            URI uri = URI.create(target);
            if (uri.getPath() != null) {
                return uri.getPath();
            }
        } catch (IllegalArgumentException ignored) {
        }

        int queryIndex = target.indexOf('?');
        return queryIndex >= 0 ? target.substring(0, queryIndex) : target;
    }

    private static String readAsciiLine(InputStream input) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        boolean sawAny = false;

        while (true) {
            int current = input.read();
            if (current < 0) {
                if (!sawAny && buffer.size() == 0) {
                    return null;
                }
                break;
            }

            sawAny = true;
            if (current == '\n') {
                break;
            }
            if (current != '\r') {
                buffer.write(current);
                if (buffer.size() > MAX_LINE_LENGTH) {
                    throw new IOException("HTTP header line too long.");
                }
            }
        }

        return buffer.toString(StandardCharsets.ISO_8859_1);
    }

    private void writeEmptyResponse(OutputStream output, int statusCode) throws IOException {
        writeResponse(output, statusCode, corsHeaders(), new byte[0]);
    }

    private void writeJsonResponse(OutputStream output, int statusCode, Map<String, ?> payload) throws IOException {
        writeJsonResponse(output, statusCode, corsHeaders(), payload);
    }

    private void writeJsonResponse(
        OutputStream output,
        int statusCode,
        Map<String, String> extraHeaders,
        Map<String, ?> payload
    ) throws IOException {
        byte[] responseBody = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(
            new LinkedHashMap<>(payload)
        );
        Map<String, String> headers = new LinkedHashMap<>(extraHeaders);
        headers.put("Content-Type", "application/json; charset=utf-8");
        writeResponse(output, statusCode, headers, responseBody);
    }

    private static void writeResponse(
        OutputStream output,
        int statusCode,
        Map<String, String> headers,
        byte[] body
    ) throws IOException {
        StringBuilder responseHead = new StringBuilder();
        responseHead.append("HTTP/1.1 ").append(statusCode).append(' ').append(reasonPhrase(statusCode)).append("\r\n");
        responseHead.append("Connection: close\r\n");
        responseHead.append("Content-Length: ").append(body.length).append("\r\n");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            responseHead.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }
        responseHead.append("\r\n");

        output.write(responseHead.toString().getBytes(StandardCharsets.ISO_8859_1));
        output.write(body);
        output.flush();
    }

    private static Map<String, String> corsHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Access-Control-Allow-Origin", "*");
        headers.put("Access-Control-Allow-Headers", "Content-Type");
        headers.put("Access-Control-Allow-Methods", "POST, OPTIONS");
        return headers;
    }

    private static String reasonPhrase(int statusCode) {
        return switch (statusCode) {
            case 200 -> "OK";
            case 202 -> "Accepted";
            case 204 -> "No Content";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 500 -> "Internal Server Error";
            default -> "Response";
        };
    }

    private static RequestRoute routeFor(String path) {
        return switch (path) {
            case EXPORT_PATH -> RequestRoute.BROWSER_EXPORT;
            case OSINT_SEED_PATH -> RequestRoute.OSINT_SEED;
            case OSINT_REPORT_PATH -> RequestRoute.OSINT_REPORT;
            default -> null;
        };
    }

    private enum RequestRoute {
        BROWSER_EXPORT,
        OSINT_SEED,
        OSINT_REPORT
    }

    private record HttpRequestData(
        String method,
        String path,
        byte[] body
    ) {}
}
