package com.blanche.burp;

import burp.api.montoya.MontoyaApi;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public final class BlancheOsintCliRunner {
    private static final long PROCESS_TIMEOUT_SECONDS = 90L;

    private final MontoyaApi api;

    public BlancheOsintCliRunner(MontoyaApi api) {
        this.api = api;
    }

    public String describeAvailability() {
        Optional<Path> cliPath = resolveCliPath();
        return cliPath
            .map(path -> "OSINT CLI: " + path)
            .orElse("OSINT CLI unavailable. Build osint-orchestrator/dist/cli.js or set BLANCHE_OSINT_CLI.");
    }

    public RunResult runSeed(String rawSeedJson) {
        Optional<Path> cliPath = resolveCliPath();
        if (cliPath.isEmpty()) {
            return new RunResult(
                false,
                false,
                "",
                "OSINT CLI unavailable. Build osint-orchestrator/dist/cli.js or set BLANCHE_OSINT_CLI.",
                ""
            );
        }

        String nodeCommand = Optional.ofNullable(System.getenv("BLANCHE_NODE_BIN"))
            .filter(value -> !value.isBlank())
            .orElse("node");

        Path seedFile = null;
        try {
            seedFile = Files.createTempFile("blanche-osint-seed-", ".json");
            Files.writeString(seedFile, rawSeedJson, StandardCharsets.UTF_8);

            ProcessBuilder builder = new ProcessBuilder(
                nodeCommand,
                cliPath.get().toString(),
                "--seed-file",
                seedFile.toString()
            );
            builder.redirectErrorStream(true);
            builder.directory(cliPath.get().getParent().getParent().toFile());

            Process process = builder.start();
            CompletableFuture<String> outputFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                } catch (IOException exception) {
                    return "";
                }
            });

            boolean finished = process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return new RunResult(
                    true,
                    false,
                    "",
                    "OSINT CLI timed out after " + PROCESS_TIMEOUT_SECONDS + " seconds.",
                    cliPath.get().toString()
                );
            }

            String output = outputFuture.get(5, TimeUnit.SECONDS).trim();
            if (process.exitValue() != 0) {
                return new RunResult(
                    true,
                    false,
                    output,
                    "OSINT CLI exited with code " + process.exitValue() + ".",
                    cliPath.get().toString()
                );
            }

            if (output.isBlank()) {
                return new RunResult(
                    true,
                    false,
                    "",
                    "OSINT CLI completed without producing JSON output.",
                    cliPath.get().toString()
                );
            }

            return new RunResult(true, true, output, "OSINT CLI completed successfully.", cliPath.get().toString());
        } catch (Exception exception) {
            api.logging().logToError("BLANCHE OSINT CLI execution failed: " + exception.getMessage());
            return new RunResult(
                true,
                false,
                "",
                "OSINT CLI execution failed: " + exception.getMessage(),
                cliPath.get().toString()
            );
        } finally {
            if (seedFile != null) {
                try {
                    Files.deleteIfExists(seedFile);
                } catch (IOException ignored) {
                }
            }
        }
    }

    private Optional<Path> resolveCliPath() {
        Optional<Path> configured = configuredCliPath();
        if (configured.isPresent()) {
            return configured;
        }

        try {
            Path location = Paths.get(
                BlancheOsintCliRunner.class.getProtectionDomain().getCodeSource().getLocation().toURI()
            ).toAbsolutePath();
            Path current = Files.isDirectory(location) ? location : location.getParent();
            for (int depth = 0; current != null && depth < 8; depth += 1) {
                Path candidate = current.resolve("osint-orchestrator").resolve("dist").resolve("cli.js");
                if (Files.isRegularFile(candidate)) {
                    return Optional.of(candidate.normalize());
                }
                current = current.getParent();
            }
        } catch (URISyntaxException exception) {
            api.logging().logToError("BLANCHE could not resolve OSINT CLI path: " + exception.getMessage());
        }

        return Optional.empty();
    }

    private Optional<Path> configuredCliPath() {
        for (String value : new String[] { System.getenv("BLANCHE_OSINT_CLI"), System.getProperty("blanche.osint.cli") }) {
            if (value == null || value.isBlank()) {
                continue;
            }

            Path candidate = Paths.get(value).toAbsolutePath().normalize();
            if (Files.isRegularFile(candidate)) {
                return Optional.of(candidate);
            }
        }

        return Optional.empty();
    }

    public record RunResult(
        boolean available,
        boolean successful,
        String outputJson,
        String message,
        String cliPath
    ) {}
}
