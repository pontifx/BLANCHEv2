// osint-orchestrator/src/cli.ts
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

// osint-orchestrator/src/collectors/dnsCollector.ts
import dns from "node:dns/promises";
var dnsCollector = {
  id: "builtin-dns",
  name: "Built-in DNS Collector",
  async run(context) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    const queryTarget = context.apparentRootDomain ?? context.primaryHostname;
    const warnings = [];
    const findings = [];
    const errors = [];
    const plans = [
      {
        label: "A",
        target: context.primaryHostname,
        resolve: async () => dns.resolve4(context.primaryHostname)
      },
      {
        label: "AAAA",
        target: context.primaryHostname,
        resolve: async () => dns.resolve6(context.primaryHostname)
      },
      {
        label: "CNAME",
        target: context.primaryHostname,
        resolve: async () => dns.resolveCname(context.primaryHostname)
      },
      {
        label: "MX",
        target: queryTarget,
        resolve: async () => dns.resolveMx(queryTarget)
      },
      {
        label: "NS",
        target: queryTarget,
        resolve: async () => dns.resolveNs(queryTarget)
      },
      {
        label: "TXT",
        target: queryTarget,
        resolve: async () => dns.resolveTxt(queryTarget)
      },
      {
        label: "SOA",
        target: queryTarget,
        resolve: async () => dns.resolveSoa(queryTarget)
      }
    ];
    for (const plan of plans) {
      try {
        const result = await plan.resolve();
        if (isEmptyResult(result)) {
          continue;
        }
        findings.push({
          findingId: createId("finding"),
          category: "dns-record",
          title: `DNS ${plan.label} records for ${plan.target}`,
          description: `Public DNS resolution returned ${plan.label} data for ${plan.target}.`,
          target: plan.target,
          confidence: "high",
          sourceTools: ["builtin-dns"],
          tags: ["dns", plan.label.toLowerCase()],
          evidence: {
            recordType: plan.label,
            target: plan.target,
            records: normalizeDnsResult(result)
          }
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (isExpectedDnsMiss(message)) {
          warnings.push({
            code: "DNS_RECORD_ABSENT",
            message: `${plan.label} lookup for ${plan.target} returned no public record.`,
            severity: "info",
            context: {
              recordType: plan.label,
              target: plan.target
            }
          });
          continue;
        }
        errors.push(`${plan.label} ${plan.target}: ${message}`);
      }
    }
    const finishedAt = (/* @__PURE__ */ new Date()).toISOString();
    return {
      toolExecution: {
        toolId: "builtin-dns",
        name: "Built-in DNS Collector",
        mode: "builtin",
        status: errors.length > 0 ? findings.length > 0 ? "partial" : "failed" : "completed",
        target: queryTarget,
        startedAt,
        finishedAt,
        outputCount: findings.length,
        warnings: warnings.map((warning) => warning.message),
        errors
      },
      findings,
      warnings,
      errors: errors.map((message) => ({
        code: "DNS_COLLECTION_FAILED",
        message,
        recoverable: true
      }))
    };
  }
};
function normalizeDnsResult(result) {
  if (Array.isArray(result)) {
    return result.map((entry) => normalizeDnsResult(entry));
  }
  if (typeof result === "object" && result !== null) {
    return Object.fromEntries(
      Object.entries(result).map(([key, value]) => [key, normalizeDnsResult(value)])
    );
  }
  if (result === null || typeof result === "string" || typeof result === "number" || typeof result === "boolean") {
    return result;
  }
  return String(result);
}
function isExpectedDnsMiss(message) {
  return ["ENODATA", "ENOTFOUND", "ESERVFAIL", "ENOTIMP"].some(
    (token) => message.toUpperCase().includes(token.toUpperCase())
  );
}
function isEmptyResult(result) {
  if (Array.isArray(result)) {
    return result.length === 0;
  }
  return result == null;
}
function createId(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}

// osint-orchestrator/src/collectors/externalToolCollector.ts
import { spawn } from "node:child_process";

// shared-schema/src/constants.ts
var BLANCHE_OSINT_SCHEMA_VERSION = "1.0.0";
var BLANCHE_OSINT_SEED_KIND = "blanche.osint-seed";
var BLANCHE_OSINT_REPORT_KIND = "blanche.osint-report";

// osint-orchestrator/src/shared/guardrails.ts
var ALLOWED_ACTIVITIES = [
  "Resolve public DNS records for in-scope hosts.",
  "Fetch public web resources such as /, robots.txt, sitemap.xml, and /.well-known/security.txt.",
  "Inspect public TLS certificate metadata presented by the target host.",
  "Run approved passive OSINT tools with non-intrusive discovery flags only."
];
var DISALLOWED_ACTIVITIES = [
  "Do not authenticate, brute force, fuzz, exploit, scan ports broadly, or validate vulnerabilities.",
  "Do not collect non-public information or bypass access controls.",
  "Do not assign severity or represent informational OSINT as validated findings.",
  "Do not replace existing ProdPT testing workflows; this output is preparatory context."
];
function createDefaultScopeStatement() {
  return {
    mode: "public-passive",
    allowedActivities: [...ALLOWED_ACTIVITIES],
    disallowedActivities: [...DISALLOWED_ACTIVITIES],
    operatorNotes: [
      "Outputs are informational and intended to guide follow-on testing, not validate security impact."
    ]
  };
}

// osint-orchestrator/src/shared/targeting.ts
function normalizeHostname(rawValue) {
  if (!rawValue) {
    return void 0;
  }
  const normalized = rawValue.trim().toLowerCase().replace(/\.$/, "");
  if (!normalized || /\s/.test(normalized)) {
    return void 0;
  }
  return normalized;
}
function deriveApparentRootDomain(hostname) {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return void 0;
  }
  const labels = normalized.split(".");
  if (labels.length <= 2) {
    return normalized;
  }
  const tld = labels.at(-1) ?? "";
  const secondLevel = labels.at(-2) ?? "";
  const commonCountryCodeSecondLevels = /* @__PURE__ */ new Set(["co", "com", "org", "net", "gov", "edu"]);
  if (tld.length === 2 && commonCountryCodeSecondLevels.has(secondLevel) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return labels.slice(-2).join(".");
}
function normalizeSeed(seed) {
  return {
    primaryHostname: seed.seed.primaryHostname,
    apparentRootDomain: seed.seed.apparentRootDomain,
    targetUrl: seed.seed.targetUrl,
    targetOrigin: seed.seed.targetOrigin
  };
}
function extractRelatedHostnames(seed) {
  const hostnames = /* @__PURE__ */ new Set();
  for (const relatedHost of seed.browserContext.relatedHosts) {
    const normalized = normalizeHostname(relatedHost.hostname);
    if (normalized) {
      hostnames.add(normalized);
    }
  }
  return [...hostnames].sort();
}
function createManualSeed(rawTarget) {
  const targetUrl = ensureUrl(rawTarget);
  const parsed = new URL(targetUrl);
  const primaryHostname = normalizeHostname(parsed.hostname);
  if (!primaryHostname) {
    throw new Error(`Unable to derive a hostname from target ${rawTarget}`);
  }
  return {
    kind: BLANCHE_OSINT_SEED_KIND,
    schemaVersion: BLANCHE_OSINT_SCHEMA_VERSION,
    seedMetadata: {
      seedId: createId2("seed"),
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
      generatedBy: {
        product: "BLANCHE",
        component: "osint-orchestrator/cli",
        version: "0.1.0"
      }
    },
    scope: createDefaultScopeStatement(),
    seed: {
      targetUrl,
      targetOrigin: parsed.origin,
      primaryHostname,
      apparentRootDomain: deriveApparentRootDomain(primaryHostname),
      sourceType: "manual"
    },
    browserContext: {
      pageUrl: targetUrl,
      pageOrigin: parsed.origin,
      apparentRootDomain: deriveApparentRootDomain(primaryHostname),
      relatedHosts: [],
      signals: {}
    },
    warnings: [
      {
        code: "MANUAL_SEED_CREATED",
        message: "The OSINT run used a manually provided target instead of a Chromium-derived seed.",
        severity: "info"
      }
    ]
  };
}
function ensureUrl(rawTarget) {
  if (/^[a-z]+:\/\//i.test(rawTarget)) {
    return rawTarget;
  }
  return `https://${rawTarget}`;
}
function createId2(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}

// osint-orchestrator/src/collectors/externalToolCollector.ts
var EXTERNAL_TOOL_SPECS = [
  {
    id: "subfinder",
    name: "subfinder",
    command: "subfinder",
    buildArgs: (target) => ["-silent", "-d", target],
    parse: (lines) => ({
      category: "hostname",
      title: "Passive subdomain enumeration via subfinder",
      description: "subfinder returned public hostnames that can expand the testing map.",
      tags: ["osint", "subdomain", "subfinder"],
      evidenceKey: "hostnames",
      values: normalizeHostnameLines(lines)
    })
  },
  {
    id: "assetfinder",
    name: "assetfinder",
    command: "assetfinder",
    buildArgs: (target) => ["--subs-only", target],
    parse: (lines) => ({
      category: "hostname",
      title: "Passive subdomain enumeration via assetfinder",
      description: "assetfinder returned public hostnames that can expand the testing map.",
      tags: ["osint", "subdomain", "assetfinder"],
      evidenceKey: "hostnames",
      values: normalizeHostnameLines(lines)
    })
  },
  {
    id: "amass-passive",
    name: "amass",
    command: "amass",
    buildArgs: (target) => ["enum", "-passive", "-norecursive", "-noalts", "-d", target],
    parse: (lines) => ({
      category: "hostname",
      title: "Passive enumeration via amass",
      description: "amass passive mode returned public hostnames that can expand the testing map.",
      tags: ["osint", "subdomain", "amass"],
      evidenceKey: "hostnames",
      values: normalizeHostnameLines(lines)
    })
  },
  {
    id: "gau",
    name: "gau",
    command: "gau",
    buildArgs: (target) => ["--subs", target],
    parse: (lines) => ({
      category: "archive-reference",
      title: "Historical URL references via gau",
      description: "gau returned archived or indexed URLs that may help prioritize follow-on review.",
      tags: ["osint", "archive", "gau"],
      evidenceKey: "urls",
      values: normalizeUrlLines(lines)
    })
  },
  {
    id: "waybackurls",
    name: "waybackurls",
    command: "waybackurls",
    buildArgs: (target) => [target],
    parse: (lines) => ({
      category: "archive-reference",
      title: "Historical URL references via waybackurls",
      description: "waybackurls returned archived URLs that may help prioritize follow-on review.",
      tags: ["osint", "archive", "wayback"],
      evidenceKey: "urls",
      values: normalizeUrlLines(lines)
    })
  }
];
var externalToolCollectors = EXTERNAL_TOOL_SPECS.map((spec) => ({
  id: `external-${spec.id}`,
  name: `External Tool: ${spec.name}`,
  async run(context) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    const warnings = [];
    const target = context.apparentRootDomain ?? deriveApparentRootDomain(context.primaryHostname) ?? context.primaryHostname;
    const args = spec.buildArgs(target);
    const commandLabel = [spec.command, ...args].join(" ");
    const processResult = await runProcess(spec.command, args, context.timeoutMs);
    if (processResult.status === "missing") {
      const message = `${spec.command} was not found on PATH; the collector was skipped.`;
      return {
        toolExecution: {
          toolId: spec.id,
          name: spec.name,
          mode: "external",
          status: "skipped",
          target,
          startedAt,
          finishedAt: (/* @__PURE__ */ new Date()).toISOString(),
          command: commandLabel,
          outputCount: 0,
          warnings: [message],
          errors: []
        },
        findings: [],
        warnings: [
          {
            code: "EXTERNAL_TOOL_MISSING",
            message,
            severity: "info",
            context: {
              toolId: spec.id
            }
          }
        ],
        errors: []
      };
    }
    const parsed = spec.parse(processResult.stdout.split(/\r?\n/).filter(Boolean));
    const finishedAt = (/* @__PURE__ */ new Date()).toISOString();
    const findings = parsed.values.length > 0 ? [
      {
        findingId: createId3("finding"),
        category: parsed.category,
        title: parsed.title,
        description: parsed.description,
        target,
        confidence: "medium",
        sourceTools: [spec.id],
        tags: parsed.tags,
        evidence: {
          [parsed.evidenceKey]: parsed.values.slice(0, 500),
          lineCount: parsed.values.length,
          command: commandLabel
        }
      }
    ] : [];
    if (processResult.stderr.trim()) {
      warnings.push({
        code: "EXTERNAL_TOOL_STDERR",
        message: `${spec.command} emitted stderr output during passive collection.`,
        severity: "info",
        context: {
          toolId: spec.id,
          stderr: processResult.stderr.slice(0, 800)
        }
      });
    }
    const errors = processResult.status === "failed" ? [processResult.errorMessage] : [];
    return {
      toolExecution: {
        toolId: spec.id,
        name: spec.name,
        mode: "external",
        status: processResult.status === "failed" ? findings.length > 0 ? "partial" : "failed" : "completed",
        target,
        startedAt,
        finishedAt,
        command: commandLabel,
        outputCount: parsed.values.length,
        warnings: warnings.map((warning) => warning.message),
        errors
      },
      findings,
      warnings,
      errors: errors.map((message) => ({
        code: "EXTERNAL_TOOL_FAILED",
        message,
        recoverable: true,
        context: {
          toolId: spec.id
        }
      }))
    };
  }
}));
function runProcess(command, args, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill();
        resolve({
          status: "failed",
          stdout,
          stderr,
          errorMessage: `timed out after ${timeoutMs}ms`
        });
      }
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      if (settled) {
        return;
      }
      settled = true;
      if ("code" in error && error.code === "ENOENT") {
        resolve({
          status: "missing",
          stdout: "",
          stderr: "",
          errorMessage: ""
        });
        return;
      }
      resolve({
        status: "failed",
        stdout,
        stderr,
        errorMessage: error.message
      });
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (settled) {
        return;
      }
      settled = true;
      if (code == 0) {
        resolve({
          status: "completed",
          stdout,
          stderr,
          errorMessage: ""
        });
        return;
      }
      resolve({
        status: "failed",
        stdout,
        stderr,
        errorMessage: `exited with code ${code ?? "unknown"}`
      });
    });
  });
}
function normalizeHostnameLines(lines) {
  const hostnames = /* @__PURE__ */ new Set();
  for (const line of lines) {
    const normalized = normalizeHostname(line);
    if (normalized) {
      hostnames.add(normalized);
    }
  }
  return [...hostnames].sort();
}
function normalizeUrlLines(lines) {
  const urls = /* @__PURE__ */ new Set();
  for (const line of lines) {
    const value = line.trim();
    if (!value) {
      continue;
    }
    try {
      urls.add(new URL(value).toString());
    } catch {
      continue;
    }
  }
  return [...urls].sort();
}
function createId3(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}

// osint-orchestrator/src/collectors/httpCollector.ts
var httpCollector = {
  id: "builtin-http",
  name: "Built-in HTTP Surface Collector",
  async run(context) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    const warnings = [];
    const findings = [];
    const errors = [];
    const baseCandidates = [`https://${context.primaryHostname}`, `http://${context.primaryHostname}`];
    const homepage = await firstSuccessfulFetch(baseCandidates, "/", context.timeoutMs);
    if (homepage) {
      findings.push(buildHomepageFinding(homepage));
      const techEvidence = extractTechnologyEvidence(homepage);
      if (Object.keys(techEvidence).length > 0) {
        findings.push({
          findingId: createId4("finding"),
          category: "technology-hint",
          title: `Public technology hints for ${context.primaryHostname}`,
          description: "The public landing page exposed response headers or HTML metadata that can guide follow-on review.",
          target: context.primaryHostname,
          confidence: "medium",
          sourceTools: ["builtin-http"],
          tags: ["http", "technology"],
          evidence: techEvidence
        });
      }
    } else {
      warnings.push({
        code: "HTTP_HOMEPAGE_UNREACHABLE",
        message: `The collector could not retrieve a public homepage for ${context.primaryHostname}.`,
        severity: "warning"
      });
    }
    const probeBase = homepage?.url.replace(/\/$/, "") ?? `https://${context.primaryHostname}`;
    const robots = await fetchText(`${probeBase}/robots.txt`, context.timeoutMs);
    if (robots.ok) {
      findings.push(buildRobotsFinding(context.primaryHostname, robots));
    } else {
      warnings.push({
        code: "ROBOTS_UNAVAILABLE",
        message: `robots.txt was not publicly available at ${probeBase}/robots.txt.`,
        severity: "info"
      });
    }
    const securityTxt = await fetchText(`${probeBase}/.well-known/security.txt`, context.timeoutMs);
    if (securityTxt.ok) {
      findings.push(buildSecurityTxtFinding(context.primaryHostname, securityTxt));
    } else {
      warnings.push({
        code: "SECURITY_TXT_UNAVAILABLE",
        message: `security.txt was not publicly available at ${probeBase}/.well-known/security.txt.`,
        severity: "info"
      });
    }
    const sitemap = await fetchText(`${probeBase}/sitemap.xml`, context.timeoutMs);
    if (sitemap.ok) {
      findings.push({
        findingId: createId4("finding"),
        category: "document-reference",
        title: `Public sitemap reference for ${context.primaryHostname}`,
        description: "A public sitemap was discoverable and can be used to widen page-level OSINT review.",
        target: context.primaryHostname,
        confidence: "high",
        sourceTools: ["builtin-http"],
        tags: ["http", "sitemap"],
        evidence: {
          url: sitemap.url,
          status: sitemap.status,
          snippet: sitemap.body.slice(0, 1200)
        }
      });
    }
    const finishedAt = (/* @__PURE__ */ new Date()).toISOString();
    return {
      toolExecution: {
        toolId: "builtin-http",
        name: "Built-in HTTP Surface Collector",
        mode: "builtin",
        status: errors.length > 0 ? findings.length > 0 ? "partial" : "failed" : "completed",
        target: context.primaryHostname,
        startedAt,
        finishedAt,
        outputCount: findings.length,
        warnings: warnings.map((warning) => warning.message),
        errors
      },
      findings,
      warnings,
      errors: errors.map((message) => ({
        code: "HTTP_COLLECTION_FAILED",
        message,
        recoverable: true
      }))
    };
  }
};
async function firstSuccessfulFetch(baseUrls, path2, timeoutMs) {
  for (const baseUrl of baseUrls) {
    const result = await fetchText(`${baseUrl}${path2}`, timeoutMs);
    if (result.ok) {
      return result;
    }
  }
  return void 0;
}
async function fetchText(url, timeoutMs) {
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        "user-agent": "BLANCHE-OSINT/0.1.0"
      }
    });
    const body = await response.text();
    return {
      url: response.url,
      ok: response.ok,
      status: response.status,
      headers: collectHeaders(response.headers),
      body: body.slice(0, 1e5)
    };
  } catch {
    return {
      url,
      ok: false,
      status: 0,
      headers: {},
      body: ""
    };
  }
}
function buildHomepageFinding(result) {
  return {
    findingId: createId4("finding"),
    category: "http-surface",
    title: `Public web surface for ${result.url}`,
    description: "The target returned a public web response that can guide scope familiarization.",
    target: result.url,
    confidence: "high",
    sourceTools: ["builtin-http"],
    tags: ["http", "headers"],
    evidence: {
      status: result.status,
      headers: result.headers,
      title: extractHtmlTitle(result.body) ?? null,
      manifestHref: extractManifestHref(result.body) ?? null
    }
  };
}
function buildRobotsFinding(hostname, result) {
  const sitemapLines = result.body.split(/\r?\n/).filter((line) => /^sitemap:/i.test(line)).slice(0, 15);
  const disallowCount = result.body.split(/\r?\n/).filter((line) => /^disallow:/i.test(line)).length;
  return {
    findingId: createId4("finding"),
    category: "document-reference",
    title: `robots.txt observations for ${hostname}`,
    description: "Public crawler policy and referenced sitemap hints were collected from robots.txt.",
    target: hostname,
    confidence: "high",
    sourceTools: ["builtin-http"],
    tags: ["http", "robots"],
    evidence: {
      url: result.url,
      status: result.status,
      disallowCount,
      sitemapReferences: sitemapLines
    }
  };
}
function buildSecurityTxtFinding(hostname, result) {
  const contacts = extractSecurityTxtValues(result.body, "contact");
  const policies = extractSecurityTxtValues(result.body, "policy");
  const acknowledgments = extractSecurityTxtValues(result.body, "acknowledgments");
  return {
    findingId: createId4("finding"),
    category: "security-contact",
    title: `security.txt contacts for ${hostname}`,
    description: "Public security contact metadata was exposed through a security.txt file.",
    target: hostname,
    confidence: "high",
    sourceTools: ["builtin-http"],
    tags: ["http", "security-txt"],
    evidence: {
      url: result.url,
      status: result.status,
      contacts,
      policies,
      acknowledgments
    }
  };
}
function extractSecurityTxtValues(body, key) {
  return body.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.toLowerCase().startsWith(`${key.toLowerCase()}:`)).map((line) => line.split(":").slice(1).join(":").trim()).filter(Boolean);
}
function extractTechnologyEvidence(result) {
  const evidence = {};
  const server = result.headers.server;
  const poweredBy = result.headers["x-powered-by"];
  const csp = result.headers["content-security-policy"];
  const hsts = result.headers["strict-transport-security"];
  const manifestHref = extractManifestHref(result.body);
  if (server) {
    evidence.server = server;
  }
  if (poweredBy) {
    evidence.xPoweredBy = poweredBy;
  }
  if (csp) {
    evidence.contentSecurityPolicy = csp;
  }
  if (hsts) {
    evidence.strictTransportSecurity = hsts;
  }
  if (manifestHref) {
    evidence.manifestHref = manifestHref;
  }
  return evidence;
}
function extractHtmlTitle(body) {
  const match = body.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match?.[1]?.trim();
}
function extractManifestHref(body) {
  const match = body.match(/<link[^>]+rel=["'][^"']*manifest[^"']*["'][^>]+href=["']([^"']+)["']/i);
  return match?.[1]?.trim();
}
function collectHeaders(headers) {
  const values = {};
  headers.forEach((value, key) => {
    values[key] = value;
  });
  return values;
}
function createId4(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}

// osint-orchestrator/src/collectors/tlsCollector.ts
import tls from "node:tls";
var tlsCollector = {
  id: "builtin-tls",
  name: "Built-in TLS Collector",
  async run(context) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    const warnings = [];
    const findings = [];
    const errors = [];
    try {
      const certificate = await connectForCertificate(context.primaryHostname, context.timeoutMs);
      findings.push({
        findingId: createId5("finding"),
        category: "tls-certificate",
        title: `TLS certificate metadata for ${context.primaryHostname}`,
        description: "The target exposed certificate metadata on TCP/443 that can reveal related names and issuance details.",
        target: context.primaryHostname,
        confidence: "high",
        sourceTools: ["builtin-tls"],
        tags: ["tls", "certificate"],
        evidence: certificate
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push({
        code: "TLS_METADATA_UNAVAILABLE",
        message: `TLS certificate metadata was unavailable for ${context.primaryHostname}: ${message}`,
        severity: "info"
      });
      errors.push(message);
    }
    const finishedAt = (/* @__PURE__ */ new Date()).toISOString();
    return {
      toolExecution: {
        toolId: "builtin-tls",
        name: "Built-in TLS Collector",
        mode: "builtin",
        status: findings.length > 0 ? "completed" : "partial",
        target: context.primaryHostname,
        startedAt,
        finishedAt,
        outputCount: findings.length,
        warnings: warnings.map((warning) => warning.message),
        errors
      },
      findings,
      warnings,
      errors: findings.length > 0 ? [] : errors.map((message) => ({
        code: "TLS_COLLECTION_FAILED",
        message,
        recoverable: true
      }))
    };
  }
};
function connectForCertificate(hostname, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false
    });
    const fail = (message) => {
      socket.destroy();
      reject(new Error(message));
    };
    socket.setTimeout(timeoutMs, () => fail(`timed out after ${timeoutMs}ms`));
    socket.on("error", (error) => fail(error.message));
    socket.on("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      socket.end();
      if (!certificate || Object.keys(certificate).length === 0) {
        reject(new Error("no peer certificate was presented"));
        return;
      }
      resolve({
        subject: stringifyCertificateField(certificate.subject),
        issuer: stringifyCertificateField(certificate.issuer),
        validFrom: certificate.valid_from ?? null,
        validTo: certificate.valid_to ?? null,
        serialNumber: certificate.serialNumber ?? null,
        fingerprint256: certificate.fingerprint256 ?? null,
        subjectAltName: certificate.subjectaltname ?? null
      });
    });
  });
}
function stringifyCertificateField(value) {
  if (value == null) {
    return null;
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}
function createId5(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}

// osint-orchestrator/src/analysis/heuristicNarrative.ts
function buildHeuristicNarrative(input) {
  const categoryCounts = countBy(input.findings.map((finding) => finding.category));
  const completedTools = input.toolExecutions.filter((tool) => tool.status === "completed").length;
  const skippedTools = input.toolExecutions.filter((tool) => tool.status === "skipped").length;
  const topCategories = Object.entries(categoryCounts).sort((left, right) => right[1] - left[1]).slice(0, 3).map(([category, count]) => `${category} (${count})`);
  const followOnFocus = /* @__PURE__ */ new Set();
  if ((categoryCounts.hostname ?? 0) > 0) {
    followOnFocus.add("Review related public hostnames and third-party endpoints before deeper testing begins.");
  }
  if ((categoryCounts["archive-reference"] ?? 0) > 0) {
    followOnFocus.add("Compare archived URL references against the current application map to spot legacy attack surface.");
  }
  if ((categoryCounts["security-contact"] ?? 0) === 0) {
    followOnFocus.add("No public security.txt contact was observed; plan coordination channels separately.");
  }
  if ((categoryCounts["technology-hint"] ?? 0) > 0) {
    followOnFocus.add("Use public technology hints to prioritize manual review paths, not to infer vulnerabilities.");
  }
  if (followOnFocus.size === 0) {
    followOnFocus.add("Use the informational OSINT findings to guide scope familiarization and request prioritization.");
  }
  return {
    headline: `Public OSINT summary for ${input.primaryHostname}`,
    summary: input.findings.length === 0 ? `No normalized OSINT findings were produced for ${input.primaryHostname}. Completed tools: ${completedTools}; skipped tools: ${skippedTools}.` : `Collected ${input.findings.length} informational findings for ${input.primaryHostname}. The strongest current themes are ${topCategories.join(", ")}. Completed tools: ${completedTools}; skipped tools: ${skippedTools}.`,
    followOnFocus: [...followOnFocus],
    reportReadyNotes: [
      "This output is informational OSINT only and does not validate vulnerabilities or business impact.",
      "Skipped tools usually indicate local environment gaps rather than absence of public data.",
      "Counts and summaries should be used to prioritize manual testing, not replace it."
    ]
  };
}
function countBy(values) {
  return values.reduce((accumulator, value) => {
    accumulator[value] = (accumulator[value] ?? 0) + 1;
    return accumulator;
  }, {});
}

// osint-orchestrator/src/report.ts
function buildOsintReport(input) {
  const findings = input.outputs.flatMap((output) => output.findings);
  const toolExecutions = input.outputs.map((output) => output.toolExecution);
  const warnings = dedupeWarnings([
    ...input.seed.warnings,
    ...input.outputs.flatMap((output) => output.warnings)
  ]);
  const errors = input.outputs.flatMap((output) => output.errors);
  const relatedHostnames = extractRelatedHostnames(input.seed);
  const narrative = buildHeuristicNarrative({
    primaryHostname: input.seed.seed.primaryHostname,
    findings,
    toolExecutions
  });
  const findingsByCategory = countBy2(findings.map((finding) => finding.category));
  return {
    kind: BLANCHE_OSINT_REPORT_KIND,
    schemaVersion: BLANCHE_OSINT_SCHEMA_VERSION,
    reportMetadata: {
      reportId: createId6("osint"),
      generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
      generatedBy: {
        product: "BLANCHE",
        component: "osint-orchestrator/cli",
        version: "0.1.0"
      },
      seedId: input.seed.seedMetadata.seedId
    },
    scope: input.seed.scope,
    target: {
      primaryHostname: input.seed.seed.primaryHostname,
      apparentRootDomain: input.seed.seed.apparentRootDomain,
      targetUrl: input.seed.seed.targetUrl,
      targetOrigin: input.seed.seed.targetOrigin,
      relatedHostnames
    },
    seed: input.seed,
    toolExecutions,
    findings,
    warnings,
    errors,
    narrative,
    summary: {
      findingCount: findings.length,
      findingsByCategory,
      completedTools: toolExecutions.filter((tool) => tool.status === "completed").length,
      skippedTools: toolExecutions.filter((tool) => tool.status === "skipped").length,
      failedTools: toolExecutions.filter((tool) => tool.status === "failed").length
    }
  };
}
function renderReportMarkdown(report) {
  const findingsSection = report.findings.length === 0 ? "- No normalized informational OSINT findings were produced.\n" : report.findings.map(
    (finding) => `- [${finding.category}] ${finding.title}: ${finding.description} (target: ${finding.target})`
  ).join("\n");
  const toolSection = report.toolExecutions.map(
    (tool) => `- ${tool.name} [${tool.status}] target=${tool.target} outputs=${tool.outputCount}${tool.command ? ` command=\`${tool.command}\`` : ""}`
  ).join("\n");
  return `# BLANCHE OSINT Summary

Generated: ${report.reportMetadata.generatedAt}
Primary Hostname: ${report.target.primaryHostname}
Target URL: ${report.target.targetUrl ?? "(not provided)"}

## Narrative

${report.narrative.headline}

${report.narrative.summary}

## Follow-On Focus

${report.narrative.followOnFocus.map((line) => `- ${line}`).join("\n")}

## Report-Ready Notes

${report.narrative.reportReadyNotes.map((line) => `- ${line}`).join("\n")}

## Tool Executions

${toolSection}

## Findings

${findingsSection}
`;
}
function dedupeWarnings(warnings) {
  const seen = /* @__PURE__ */ new Set();
  const output = [];
  for (const warning of warnings) {
    const key = JSON.stringify(warning);
    if (!seen.has(key)) {
      seen.add(key);
      output.push(warning);
    }
  }
  return output;
}
function countBy2(values) {
  return values.reduce((accumulator, value) => {
    accumulator[value] = (accumulator[value] ?? 0) + 1;
    return accumulator;
  }, {});
}
function createId6(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}

// osint-orchestrator/src/cli.ts
var options = parseArgs(process.argv.slice(2));
if (!options.seedFile && !options.target) {
  printUsage();
  process.exitCode = 1;
} else {
  void run(options).catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
async function run(options2) {
  const seed = options2.seedFile ? await loadSeed(options2.seedFile) : createManualSeed(options2.target ?? "");
  const normalized = normalizeSeed(seed);
  const relatedHostnames = extractRelatedHostnames(seed);
  const collectors = [dnsCollector, httpCollector, tlsCollector];
  if (options2.includeExternalTools) {
    collectors.push(...externalToolCollectors);
  }
  const outputs = await Promise.all(
    collectors.map(
      (collector) => collector.run({
        seed,
        primaryHostname: normalized.primaryHostname,
        apparentRootDomain: normalized.apparentRootDomain,
        relatedHostnames,
        timeoutMs: options2.timeoutMs
      })
    )
  );
  const report = buildOsintReport({
    seed,
    outputs
  });
  if (options2.outputDir) {
    await writeArtifacts(options2.outputDir, report);
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}
`);
}
async function loadSeed(seedFile) {
  const raw = await fs.readFile(seedFile, "utf8");
  const parsed = JSON.parse(raw);
  if (parsed.kind !== "blanche.osint-seed") {
    throw new Error(`Unsupported seed payload kind in ${seedFile}`);
  }
  if (!parsed.seed?.primaryHostname) {
    throw new Error(`Seed payload in ${seedFile} is missing seed.primaryHostname`);
  }
  return parsed;
}
async function writeArtifacts(outputDir, report) {
  await fs.mkdir(outputDir, { recursive: true });
  const timestamp = report.reportMetadata.generatedAt.replaceAll(":", "-");
  const hostnameStem = report.target.primaryHostname.replaceAll(/[^a-z0-9.-]/gi, "_");
  const jsonPath = path.join(outputDir, `${hostnameStem}_${timestamp}.json`);
  const markdownPath = path.join(outputDir, `${hostnameStem}_${timestamp}.md`);
  await fs.writeFile(jsonPath, `${JSON.stringify(report, null, 2)}
`, "utf8");
  await fs.writeFile(markdownPath, renderReportMarkdown(report), "utf8");
}
function parseArgs(argv) {
  const options2 = {
    timeoutMs: 8e3,
    includeExternalTools: true
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case "--seed-file":
        options2.seedFile = argv[index + 1];
        index += 1;
        break;
      case "--target":
        options2.target = argv[index + 1];
        index += 1;
        break;
      case "--output-dir":
        options2.outputDir = argv[index + 1];
        index += 1;
        break;
      case "--timeout-ms":
        options2.timeoutMs = Number(argv[index + 1] ?? options2.timeoutMs);
        index += 1;
        break;
      case "--no-external-tools":
        options2.includeExternalTools = false;
        break;
      case "--help":
        printUsage();
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return options2;
}
function printUsage() {
  process.stdout.write(`BLANCHE OSINT Orchestrator

Usage:
  node osint-orchestrator/dist/cli.js --seed-file <path> [--output-dir <dir>] [--timeout-ms <ms>]
  node osint-orchestrator/dist/cli.js --target <hostname-or-url> [--output-dir <dir>] [--no-external-tools]
`);
}
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2NsaS50cyIsICIuLi9zcmMvY29sbGVjdG9ycy9kbnNDb2xsZWN0b3IudHMiLCAiLi4vc3JjL2NvbGxlY3RvcnMvZXh0ZXJuYWxUb29sQ29sbGVjdG9yLnRzIiwgIi4uLy4uL3NoYXJlZC1zY2hlbWEvc3JjL2NvbnN0YW50cy50cyIsICIuLi9zcmMvc2hhcmVkL2d1YXJkcmFpbHMudHMiLCAiLi4vc3JjL3NoYXJlZC90YXJnZXRpbmcudHMiLCAiLi4vc3JjL2NvbGxlY3RvcnMvaHR0cENvbGxlY3Rvci50cyIsICIuLi9zcmMvY29sbGVjdG9ycy90bHNDb2xsZWN0b3IudHMiLCAiLi4vc3JjL2FuYWx5c2lzL2hldXJpc3RpY05hcnJhdGl2ZS50cyIsICIuLi9zcmMvcmVwb3J0LnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgZnMgZnJvbSAnbm9kZTpmcy9wcm9taXNlcyc7XG5pbXBvcnQgcGF0aCBmcm9tICdub2RlOnBhdGgnO1xuaW1wb3J0IHByb2Nlc3MgZnJvbSAnbm9kZTpwcm9jZXNzJztcbmltcG9ydCB0eXBlIHsgQmxhbmNoZU9zaW50U2VlZFYxIH0gZnJvbSAnLi4vLi4vc2hhcmVkLXNjaGVtYS9zcmMnO1xuaW1wb3J0IHsgZG5zQ29sbGVjdG9yIH0gZnJvbSAnLi9jb2xsZWN0b3JzL2Ruc0NvbGxlY3Rvcic7XG5pbXBvcnQgeyBleHRlcm5hbFRvb2xDb2xsZWN0b3JzIH0gZnJvbSAnLi9jb2xsZWN0b3JzL2V4dGVybmFsVG9vbENvbGxlY3Rvcic7XG5pbXBvcnQgeyBodHRwQ29sbGVjdG9yIH0gZnJvbSAnLi9jb2xsZWN0b3JzL2h0dHBDb2xsZWN0b3InO1xuaW1wb3J0IHsgdGxzQ29sbGVjdG9yIH0gZnJvbSAnLi9jb2xsZWN0b3JzL3Rsc0NvbGxlY3Rvcic7XG5pbXBvcnQgdHlwZSB7IENvbGxlY3RvckRlZmluaXRpb24gfSBmcm9tICcuL2NvbGxlY3RvcnMvdHlwZXMnO1xuaW1wb3J0IHsgYnVpbGRPc2ludFJlcG9ydCwgcmVuZGVyUmVwb3J0TWFya2Rvd24gfSBmcm9tICcuL3JlcG9ydCc7XG5pbXBvcnQgeyBjcmVhdGVNYW51YWxTZWVkLCBleHRyYWN0UmVsYXRlZEhvc3RuYW1lcywgbm9ybWFsaXplU2VlZCB9IGZyb20gJy4vc2hhcmVkL3RhcmdldGluZyc7XG5cbmludGVyZmFjZSBDbGlPcHRpb25zIHtcbiAgc2VlZEZpbGU/OiBzdHJpbmc7XG4gIHRhcmdldD86IHN0cmluZztcbiAgb3V0cHV0RGlyPzogc3RyaW5nO1xuICB0aW1lb3V0TXM6IG51bWJlcjtcbiAgaW5jbHVkZUV4dGVybmFsVG9vbHM6IGJvb2xlYW47XG59XG5cbmNvbnN0IG9wdGlvbnMgPSBwYXJzZUFyZ3MocHJvY2Vzcy5hcmd2LnNsaWNlKDIpKTtcbmlmICghb3B0aW9ucy5zZWVkRmlsZSAmJiAhb3B0aW9ucy50YXJnZXQpIHtcbiAgcHJpbnRVc2FnZSgpO1xuICBwcm9jZXNzLmV4aXRDb2RlID0gMTtcbn0gZWxzZSB7XG4gIHZvaWQgcnVuKG9wdGlvbnMpLmNhdGNoKChlcnJvcikgPT4ge1xuICAgIGNvbnN0IG1lc3NhZ2UgPSBlcnJvciBpbnN0YW5jZW9mIEVycm9yID8gZXJyb3IubWVzc2FnZSA6IFN0cmluZyhlcnJvcik7XG4gICAgY29uc29sZS5lcnJvcihtZXNzYWdlKTtcbiAgICBwcm9jZXNzLmV4aXRDb2RlID0gMTtcbiAgfSk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHJ1bihvcHRpb25zOiBDbGlPcHRpb25zKTogUHJvbWlzZTx2b2lkPiB7XG4gIGNvbnN0IHNlZWQgPSBvcHRpb25zLnNlZWRGaWxlID8gYXdhaXQgbG9hZFNlZWQob3B0aW9ucy5zZWVkRmlsZSkgOiBjcmVhdGVNYW51YWxTZWVkKG9wdGlvbnMudGFyZ2V0ID8/ICcnKTtcbiAgY29uc3Qgbm9ybWFsaXplZCA9IG5vcm1hbGl6ZVNlZWQoc2VlZCk7XG4gIGNvbnN0IHJlbGF0ZWRIb3N0bmFtZXMgPSBleHRyYWN0UmVsYXRlZEhvc3RuYW1lcyhzZWVkKTtcblxuICBjb25zdCBjb2xsZWN0b3JzOiBDb2xsZWN0b3JEZWZpbml0aW9uW10gPSBbZG5zQ29sbGVjdG9yLCBodHRwQ29sbGVjdG9yLCB0bHNDb2xsZWN0b3JdO1xuICBpZiAob3B0aW9ucy5pbmNsdWRlRXh0ZXJuYWxUb29scykge1xuICAgIGNvbGxlY3RvcnMucHVzaCguLi5leHRlcm5hbFRvb2xDb2xsZWN0b3JzKTtcbiAgfVxuXG4gIGNvbnN0IG91dHB1dHMgPSBhd2FpdCBQcm9taXNlLmFsbChcbiAgICBjb2xsZWN0b3JzLm1hcCgoY29sbGVjdG9yKSA9PlxuICAgICAgY29sbGVjdG9yLnJ1bih7XG4gICAgICAgIHNlZWQsXG4gICAgICAgIHByaW1hcnlIb3N0bmFtZTogbm9ybWFsaXplZC5wcmltYXJ5SG9zdG5hbWUsXG4gICAgICAgIGFwcGFyZW50Um9vdERvbWFpbjogbm9ybWFsaXplZC5hcHBhcmVudFJvb3REb21haW4sXG4gICAgICAgIHJlbGF0ZWRIb3N0bmFtZXMsXG4gICAgICAgIHRpbWVvdXRNczogb3B0aW9ucy50aW1lb3V0TXNcbiAgICAgIH0pXG4gICAgKVxuICApO1xuXG4gIGNvbnN0IHJlcG9ydCA9IGJ1aWxkT3NpbnRSZXBvcnQoe1xuICAgIHNlZWQsXG4gICAgb3V0cHV0c1xuICB9KTtcblxuICBpZiAob3B0aW9ucy5vdXRwdXREaXIpIHtcbiAgICBhd2FpdCB3cml0ZUFydGlmYWN0cyhvcHRpb25zLm91dHB1dERpciwgcmVwb3J0KTtcbiAgfVxuXG4gIHByb2Nlc3Muc3Rkb3V0LndyaXRlKGAke0pTT04uc3RyaW5naWZ5KHJlcG9ydCwgbnVsbCwgMil9XFxuYCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGxvYWRTZWVkKHNlZWRGaWxlOiBzdHJpbmcpOiBQcm9taXNlPEJsYW5jaGVPc2ludFNlZWRWMT4ge1xuICBjb25zdCByYXcgPSBhd2FpdCBmcy5yZWFkRmlsZShzZWVkRmlsZSwgJ3V0ZjgnKTtcbiAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShyYXcpIGFzIFBhcnRpYWw8QmxhbmNoZU9zaW50U2VlZFYxPjtcbiAgaWYgKHBhcnNlZC5raW5kICE9PSAnYmxhbmNoZS5vc2ludC1zZWVkJykge1xuICAgIHRocm93IG5ldyBFcnJvcihgVW5zdXBwb3J0ZWQgc2VlZCBwYXlsb2FkIGtpbmQgaW4gJHtzZWVkRmlsZX1gKTtcbiAgfVxuICBpZiAoIXBhcnNlZC5zZWVkPy5wcmltYXJ5SG9zdG5hbWUpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYFNlZWQgcGF5bG9hZCBpbiAke3NlZWRGaWxlfSBpcyBtaXNzaW5nIHNlZWQucHJpbWFyeUhvc3RuYW1lYCk7XG4gIH1cbiAgcmV0dXJuIHBhcnNlZCBhcyBCbGFuY2hlT3NpbnRTZWVkVjE7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHdyaXRlQXJ0aWZhY3RzKG91dHB1dERpcjogc3RyaW5nLCByZXBvcnQ6IFJldHVyblR5cGU8dHlwZW9mIGJ1aWxkT3NpbnRSZXBvcnQ+KTogUHJvbWlzZTx2b2lkPiB7XG4gIGF3YWl0IGZzLm1rZGlyKG91dHB1dERpciwgeyByZWN1cnNpdmU6IHRydWUgfSk7XG4gIGNvbnN0IHRpbWVzdGFtcCA9IHJlcG9ydC5yZXBvcnRNZXRhZGF0YS5nZW5lcmF0ZWRBdC5yZXBsYWNlQWxsKCc6JywgJy0nKTtcbiAgY29uc3QgaG9zdG5hbWVTdGVtID0gcmVwb3J0LnRhcmdldC5wcmltYXJ5SG9zdG5hbWUucmVwbGFjZUFsbCgvW15hLXowLTkuLV0vZ2ksICdfJyk7XG4gIGNvbnN0IGpzb25QYXRoID0gcGF0aC5qb2luKG91dHB1dERpciwgYCR7aG9zdG5hbWVTdGVtfV8ke3RpbWVzdGFtcH0uanNvbmApO1xuICBjb25zdCBtYXJrZG93blBhdGggPSBwYXRoLmpvaW4ob3V0cHV0RGlyLCBgJHtob3N0bmFtZVN0ZW19XyR7dGltZXN0YW1wfS5tZGApO1xuICBhd2FpdCBmcy53cml0ZUZpbGUoanNvblBhdGgsIGAke0pTT04uc3RyaW5naWZ5KHJlcG9ydCwgbnVsbCwgMil9XFxuYCwgJ3V0ZjgnKTtcbiAgYXdhaXQgZnMud3JpdGVGaWxlKG1hcmtkb3duUGF0aCwgcmVuZGVyUmVwb3J0TWFya2Rvd24ocmVwb3J0KSwgJ3V0ZjgnKTtcbn1cblxuZnVuY3Rpb24gcGFyc2VBcmdzKGFyZ3Y6IHN0cmluZ1tdKTogQ2xpT3B0aW9ucyB7XG4gIGNvbnN0IG9wdGlvbnM6IENsaU9wdGlvbnMgPSB7XG4gICAgdGltZW91dE1zOiA4MDAwLFxuICAgIGluY2x1ZGVFeHRlcm5hbFRvb2xzOiB0cnVlXG4gIH07XG5cbiAgZm9yIChsZXQgaW5kZXggPSAwOyBpbmRleCA8IGFyZ3YubGVuZ3RoOyBpbmRleCArPSAxKSB7XG4gICAgY29uc3QgYXJndW1lbnQgPSBhcmd2W2luZGV4XTtcbiAgICBzd2l0Y2ggKGFyZ3VtZW50KSB7XG4gICAgICBjYXNlICctLXNlZWQtZmlsZSc6XG4gICAgICAgIG9wdGlvbnMuc2VlZEZpbGUgPSBhcmd2W2luZGV4ICsgMV07XG4gICAgICAgIGluZGV4ICs9IDE7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnLS10YXJnZXQnOlxuICAgICAgICBvcHRpb25zLnRhcmdldCA9IGFyZ3ZbaW5kZXggKyAxXTtcbiAgICAgICAgaW5kZXggKz0gMTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICctLW91dHB1dC1kaXInOlxuICAgICAgICBvcHRpb25zLm91dHB1dERpciA9IGFyZ3ZbaW5kZXggKyAxXTtcbiAgICAgICAgaW5kZXggKz0gMTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICctLXRpbWVvdXQtbXMnOlxuICAgICAgICBvcHRpb25zLnRpbWVvdXRNcyA9IE51bWJlcihhcmd2W2luZGV4ICsgMV0gPz8gb3B0aW9ucy50aW1lb3V0TXMpO1xuICAgICAgICBpbmRleCArPSAxO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJy0tbm8tZXh0ZXJuYWwtdG9vbHMnOlxuICAgICAgICBvcHRpb25zLmluY2x1ZGVFeHRlcm5hbFRvb2xzID0gZmFsc2U7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnLS1oZWxwJzpcbiAgICAgICAgcHJpbnRVc2FnZSgpO1xuICAgICAgICBwcm9jZXNzLmV4aXQoMCk7XG4gICAgICBkZWZhdWx0OlxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYFVua25vd24gYXJndW1lbnQ6ICR7YXJndW1lbnR9YCk7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIG9wdGlvbnM7XG59XG5cbmZ1bmN0aW9uIHByaW50VXNhZ2UoKTogdm9pZCB7XG4gIHByb2Nlc3Muc3Rkb3V0LndyaXRlKGBCTEFOQ0hFIE9TSU5UIE9yY2hlc3RyYXRvclxuXG5Vc2FnZTpcbiAgbm9kZSBvc2ludC1vcmNoZXN0cmF0b3IvZGlzdC9jbGkuanMgLS1zZWVkLWZpbGUgPHBhdGg+IFstLW91dHB1dC1kaXIgPGRpcj5dIFstLXRpbWVvdXQtbXMgPG1zPl1cbiAgbm9kZSBvc2ludC1vcmNoZXN0cmF0b3IvZGlzdC9jbGkuanMgLS10YXJnZXQgPGhvc3RuYW1lLW9yLXVybD4gWy0tb3V0cHV0LWRpciA8ZGlyPl0gWy0tbm8tZXh0ZXJuYWwtdG9vbHNdXG5gKTtcbn1cbiIsICJpbXBvcnQgZG5zIGZyb20gJ25vZGU6ZG5zL3Byb21pc2VzJztcbmltcG9ydCB0eXBlIHsgRXhwb3J0V2FybmluZywgSnNvblZhbHVlLCBPc2ludEZpbmRpbmcgfSBmcm9tICcuLi8uLi8uLi9zaGFyZWQtc2NoZW1hL3NyYyc7XG5pbXBvcnQgdHlwZSB7IENvbGxlY3RvckRlZmluaXRpb24sIENvbGxlY3RvclJ1bk91dHB1dCB9IGZyb20gJy4vdHlwZXMnO1xuXG5pbnRlcmZhY2UgUXVlcnlQbGFuIHtcbiAgbGFiZWw6IHN0cmluZztcbiAgdGFyZ2V0OiBzdHJpbmc7XG4gIHJlc29sdmUoKTogUHJvbWlzZTx1bmtub3duPjtcbn1cblxuZXhwb3J0IGNvbnN0IGRuc0NvbGxlY3RvcjogQ29sbGVjdG9yRGVmaW5pdGlvbiA9IHtcbiAgaWQ6ICdidWlsdGluLWRucycsXG4gIG5hbWU6ICdCdWlsdC1pbiBETlMgQ29sbGVjdG9yJyxcbiAgYXN5bmMgcnVuKGNvbnRleHQpOiBQcm9taXNlPENvbGxlY3RvclJ1bk91dHB1dD4ge1xuICAgIGNvbnN0IHN0YXJ0ZWRBdCA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICBjb25zdCBxdWVyeVRhcmdldCA9IGNvbnRleHQuYXBwYXJlbnRSb290RG9tYWluID8/IGNvbnRleHQucHJpbWFyeUhvc3RuYW1lO1xuICAgIGNvbnN0IHdhcm5pbmdzOiBFeHBvcnRXYXJuaW5nW10gPSBbXTtcbiAgICBjb25zdCBmaW5kaW5nczogT3NpbnRGaW5kaW5nW10gPSBbXTtcbiAgICBjb25zdCBlcnJvcnM6IHN0cmluZ1tdID0gW107XG5cbiAgICBjb25zdCBwbGFuczogUXVlcnlQbGFuW10gPSBbXG4gICAgICB7XG4gICAgICAgIGxhYmVsOiAnQScsXG4gICAgICAgIHRhcmdldDogY29udGV4dC5wcmltYXJ5SG9zdG5hbWUsXG4gICAgICAgIHJlc29sdmU6IGFzeW5jICgpID0+IGRucy5yZXNvbHZlNChjb250ZXh0LnByaW1hcnlIb3N0bmFtZSlcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIGxhYmVsOiAnQUFBQScsXG4gICAgICAgIHRhcmdldDogY29udGV4dC5wcmltYXJ5SG9zdG5hbWUsXG4gICAgICAgIHJlc29sdmU6IGFzeW5jICgpID0+IGRucy5yZXNvbHZlNihjb250ZXh0LnByaW1hcnlIb3N0bmFtZSlcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIGxhYmVsOiAnQ05BTUUnLFxuICAgICAgICB0YXJnZXQ6IGNvbnRleHQucHJpbWFyeUhvc3RuYW1lLFxuICAgICAgICByZXNvbHZlOiBhc3luYyAoKSA9PiBkbnMucmVzb2x2ZUNuYW1lKGNvbnRleHQucHJpbWFyeUhvc3RuYW1lKVxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgbGFiZWw6ICdNWCcsXG4gICAgICAgIHRhcmdldDogcXVlcnlUYXJnZXQsXG4gICAgICAgIHJlc29sdmU6IGFzeW5jICgpID0+IGRucy5yZXNvbHZlTXgocXVlcnlUYXJnZXQpXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBsYWJlbDogJ05TJyxcbiAgICAgICAgdGFyZ2V0OiBxdWVyeVRhcmdldCxcbiAgICAgICAgcmVzb2x2ZTogYXN5bmMgKCkgPT4gZG5zLnJlc29sdmVOcyhxdWVyeVRhcmdldClcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIGxhYmVsOiAnVFhUJyxcbiAgICAgICAgdGFyZ2V0OiBxdWVyeVRhcmdldCxcbiAgICAgICAgcmVzb2x2ZTogYXN5bmMgKCkgPT4gZG5zLnJlc29sdmVUeHQocXVlcnlUYXJnZXQpXG4gICAgICB9LFxuICAgICAge1xuICAgICAgICBsYWJlbDogJ1NPQScsXG4gICAgICAgIHRhcmdldDogcXVlcnlUYXJnZXQsXG4gICAgICAgIHJlc29sdmU6IGFzeW5jICgpID0+IGRucy5yZXNvbHZlU29hKHF1ZXJ5VGFyZ2V0KVxuICAgICAgfVxuICAgIF07XG5cbiAgICBmb3IgKGNvbnN0IHBsYW4gb2YgcGxhbnMpIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHBsYW4ucmVzb2x2ZSgpO1xuICAgICAgICBpZiAoaXNFbXB0eVJlc3VsdChyZXN1bHQpKSB7XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cblxuICAgICAgICBmaW5kaW5ncy5wdXNoKHtcbiAgICAgICAgICBmaW5kaW5nSWQ6IGNyZWF0ZUlkKCdmaW5kaW5nJyksXG4gICAgICAgICAgY2F0ZWdvcnk6ICdkbnMtcmVjb3JkJyxcbiAgICAgICAgICB0aXRsZTogYEROUyAke3BsYW4ubGFiZWx9IHJlY29yZHMgZm9yICR7cGxhbi50YXJnZXR9YCxcbiAgICAgICAgICBkZXNjcmlwdGlvbjogYFB1YmxpYyBETlMgcmVzb2x1dGlvbiByZXR1cm5lZCAke3BsYW4ubGFiZWx9IGRhdGEgZm9yICR7cGxhbi50YXJnZXR9LmAsXG4gICAgICAgICAgdGFyZ2V0OiBwbGFuLnRhcmdldCxcbiAgICAgICAgICBjb25maWRlbmNlOiAnaGlnaCcsXG4gICAgICAgICAgc291cmNlVG9vbHM6IFsnYnVpbHRpbi1kbnMnXSxcbiAgICAgICAgICB0YWdzOiBbJ2RucycsIHBsYW4ubGFiZWwudG9Mb3dlckNhc2UoKV0sXG4gICAgICAgICAgZXZpZGVuY2U6IHtcbiAgICAgICAgICAgIHJlY29yZFR5cGU6IHBsYW4ubGFiZWwsXG4gICAgICAgICAgICB0YXJnZXQ6IHBsYW4udGFyZ2V0LFxuICAgICAgICAgICAgcmVjb3Jkczogbm9ybWFsaXplRG5zUmVzdWx0KHJlc3VsdClcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc3QgbWVzc2FnZSA9IGVycm9yIGluc3RhbmNlb2YgRXJyb3IgPyBlcnJvci5tZXNzYWdlIDogU3RyaW5nKGVycm9yKTtcbiAgICAgICAgaWYgKGlzRXhwZWN0ZWREbnNNaXNzKG1lc3NhZ2UpKSB7XG4gICAgICAgICAgd2FybmluZ3MucHVzaCh7XG4gICAgICAgICAgICBjb2RlOiAnRE5TX1JFQ09SRF9BQlNFTlQnLFxuICAgICAgICAgICAgbWVzc2FnZTogYCR7cGxhbi5sYWJlbH0gbG9va3VwIGZvciAke3BsYW4udGFyZ2V0fSByZXR1cm5lZCBubyBwdWJsaWMgcmVjb3JkLmAsXG4gICAgICAgICAgICBzZXZlcml0eTogJ2luZm8nLFxuICAgICAgICAgICAgY29udGV4dDoge1xuICAgICAgICAgICAgICByZWNvcmRUeXBlOiBwbGFuLmxhYmVsLFxuICAgICAgICAgICAgICB0YXJnZXQ6IHBsYW4udGFyZ2V0XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cblxuICAgICAgICBlcnJvcnMucHVzaChgJHtwbGFuLmxhYmVsfSAke3BsYW4udGFyZ2V0fTogJHttZXNzYWdlfWApO1xuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IGZpbmlzaGVkQXQgPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCk7XG4gICAgcmV0dXJuIHtcbiAgICAgIHRvb2xFeGVjdXRpb246IHtcbiAgICAgICAgdG9vbElkOiAnYnVpbHRpbi1kbnMnLFxuICAgICAgICBuYW1lOiAnQnVpbHQtaW4gRE5TIENvbGxlY3RvcicsXG4gICAgICAgIG1vZGU6ICdidWlsdGluJyxcbiAgICAgICAgc3RhdHVzOiBlcnJvcnMubGVuZ3RoID4gMCA/IChmaW5kaW5ncy5sZW5ndGggPiAwID8gJ3BhcnRpYWwnIDogJ2ZhaWxlZCcpIDogJ2NvbXBsZXRlZCcsXG4gICAgICAgIHRhcmdldDogcXVlcnlUYXJnZXQsXG4gICAgICAgIHN0YXJ0ZWRBdCxcbiAgICAgICAgZmluaXNoZWRBdCxcbiAgICAgICAgb3V0cHV0Q291bnQ6IGZpbmRpbmdzLmxlbmd0aCxcbiAgICAgICAgd2FybmluZ3M6IHdhcm5pbmdzLm1hcCgod2FybmluZykgPT4gd2FybmluZy5tZXNzYWdlKSxcbiAgICAgICAgZXJyb3JzXG4gICAgICB9LFxuICAgICAgZmluZGluZ3MsXG4gICAgICB3YXJuaW5ncyxcbiAgICAgIGVycm9yczogZXJyb3JzLm1hcCgobWVzc2FnZSkgPT4gKHtcbiAgICAgICAgY29kZTogJ0ROU19DT0xMRUNUSU9OX0ZBSUxFRCcsXG4gICAgICAgIG1lc3NhZ2UsXG4gICAgICAgIHJlY292ZXJhYmxlOiB0cnVlXG4gICAgICB9KSlcbiAgICB9O1xuICB9XG59O1xuXG5mdW5jdGlvbiBub3JtYWxpemVEbnNSZXN1bHQocmVzdWx0OiB1bmtub3duKTogSnNvblZhbHVlIHtcbiAgaWYgKEFycmF5LmlzQXJyYXkocmVzdWx0KSkge1xuICAgIHJldHVybiByZXN1bHQubWFwKChlbnRyeSkgPT4gbm9ybWFsaXplRG5zUmVzdWx0KGVudHJ5KSk7XG4gIH1cblxuICBpZiAodHlwZW9mIHJlc3VsdCA9PT0gJ29iamVjdCcgJiYgcmVzdWx0ICE9PSBudWxsKSB7XG4gICAgcmV0dXJuIE9iamVjdC5mcm9tRW50cmllcyhcbiAgICAgIE9iamVjdC5lbnRyaWVzKHJlc3VsdCkubWFwKChba2V5LCB2YWx1ZV0pID0+IFtrZXksIG5vcm1hbGl6ZURuc1Jlc3VsdCh2YWx1ZSldKVxuICAgICk7XG4gIH1cblxuICBpZiAoXG4gICAgcmVzdWx0ID09PSBudWxsIHx8XG4gICAgdHlwZW9mIHJlc3VsdCA9PT0gJ3N0cmluZycgfHxcbiAgICB0eXBlb2YgcmVzdWx0ID09PSAnbnVtYmVyJyB8fFxuICAgIHR5cGVvZiByZXN1bHQgPT09ICdib29sZWFuJ1xuICApIHtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgcmV0dXJuIFN0cmluZyhyZXN1bHQpO1xufVxuXG5mdW5jdGlvbiBpc0V4cGVjdGVkRG5zTWlzcyhtZXNzYWdlOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgcmV0dXJuIFsnRU5PREFUQScsICdFTk9URk9VTkQnLCAnRVNFUlZGQUlMJywgJ0VOT1RJTVAnXS5zb21lKCh0b2tlbikgPT5cbiAgICBtZXNzYWdlLnRvVXBwZXJDYXNlKCkuaW5jbHVkZXModG9rZW4udG9VcHBlckNhc2UoKSlcbiAgKTtcbn1cblxuZnVuY3Rpb24gaXNFbXB0eVJlc3VsdChyZXN1bHQ6IHVua25vd24pOiBib29sZWFuIHtcbiAgaWYgKEFycmF5LmlzQXJyYXkocmVzdWx0KSkge1xuICAgIHJldHVybiByZXN1bHQubGVuZ3RoID09PSAwO1xuICB9XG5cbiAgcmV0dXJuIHJlc3VsdCA9PSBudWxsO1xufVxuXG5mdW5jdGlvbiBjcmVhdGVJZChwcmVmaXg6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiBgJHtwcmVmaXh9XyR7RGF0ZS5ub3coKS50b1N0cmluZygzNil9XyR7Y3J5cHRvLnJhbmRvbVVVSUQoKX1gO1xufVxuIiwgImltcG9ydCB7IHNwYXduIH0gZnJvbSAnbm9kZTpjaGlsZF9wcm9jZXNzJztcbmltcG9ydCB0eXBlIHsgRXhwb3J0V2FybmluZywgT3NpbnRGaW5kaW5nIH0gZnJvbSAnLi4vLi4vLi4vc2hhcmVkLXNjaGVtYS9zcmMnO1xuaW1wb3J0IHsgZGVyaXZlQXBwYXJlbnRSb290RG9tYWluLCBub3JtYWxpemVIb3N0bmFtZSB9IGZyb20gJy4uL3NoYXJlZC90YXJnZXRpbmcnO1xuaW1wb3J0IHR5cGUgeyBDb2xsZWN0b3JEZWZpbml0aW9uLCBDb2xsZWN0b3JSdW5PdXRwdXQgfSBmcm9tICcuL3R5cGVzJztcblxuaW50ZXJmYWNlIEV4dGVybmFsVG9vbFNwZWMge1xuICBpZDogc3RyaW5nO1xuICBuYW1lOiBzdHJpbmc7XG4gIGNvbW1hbmQ6IHN0cmluZztcbiAgYnVpbGRBcmdzKHRhcmdldDogc3RyaW5nKTogc3RyaW5nW107XG4gIHBhcnNlKGxpbmVzOiBzdHJpbmdbXSk6IHtcbiAgICBjYXRlZ29yeTogT3NpbnRGaW5kaW5nWydjYXRlZ29yeSddO1xuICAgIHRpdGxlOiBzdHJpbmc7XG4gICAgZGVzY3JpcHRpb246IHN0cmluZztcbiAgICB0YWdzOiBzdHJpbmdbXTtcbiAgICBldmlkZW5jZUtleTogc3RyaW5nO1xuICAgIHZhbHVlczogc3RyaW5nW107XG4gIH07XG59XG5cbmNvbnN0IEVYVEVSTkFMX1RPT0xfU1BFQ1M6IEV4dGVybmFsVG9vbFNwZWNbXSA9IFtcbiAge1xuICAgIGlkOiAnc3ViZmluZGVyJyxcbiAgICBuYW1lOiAnc3ViZmluZGVyJyxcbiAgICBjb21tYW5kOiAnc3ViZmluZGVyJyxcbiAgICBidWlsZEFyZ3M6ICh0YXJnZXQpID0+IFsnLXNpbGVudCcsICctZCcsIHRhcmdldF0sXG4gICAgcGFyc2U6IChsaW5lcykgPT4gKHtcbiAgICAgIGNhdGVnb3J5OiAnaG9zdG5hbWUnLFxuICAgICAgdGl0bGU6ICdQYXNzaXZlIHN1YmRvbWFpbiBlbnVtZXJhdGlvbiB2aWEgc3ViZmluZGVyJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnc3ViZmluZGVyIHJldHVybmVkIHB1YmxpYyBob3N0bmFtZXMgdGhhdCBjYW4gZXhwYW5kIHRoZSB0ZXN0aW5nIG1hcC4nLFxuICAgICAgdGFnczogWydvc2ludCcsICdzdWJkb21haW4nLCAnc3ViZmluZGVyJ10sXG4gICAgICBldmlkZW5jZUtleTogJ2hvc3RuYW1lcycsXG4gICAgICB2YWx1ZXM6IG5vcm1hbGl6ZUhvc3RuYW1lTGluZXMobGluZXMpXG4gICAgfSlcbiAgfSxcbiAge1xuICAgIGlkOiAnYXNzZXRmaW5kZXInLFxuICAgIG5hbWU6ICdhc3NldGZpbmRlcicsXG4gICAgY29tbWFuZDogJ2Fzc2V0ZmluZGVyJyxcbiAgICBidWlsZEFyZ3M6ICh0YXJnZXQpID0+IFsnLS1zdWJzLW9ubHknLCB0YXJnZXRdLFxuICAgIHBhcnNlOiAobGluZXMpID0+ICh7XG4gICAgICBjYXRlZ29yeTogJ2hvc3RuYW1lJyxcbiAgICAgIHRpdGxlOiAnUGFzc2l2ZSBzdWJkb21haW4gZW51bWVyYXRpb24gdmlhIGFzc2V0ZmluZGVyJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnYXNzZXRmaW5kZXIgcmV0dXJuZWQgcHVibGljIGhvc3RuYW1lcyB0aGF0IGNhbiBleHBhbmQgdGhlIHRlc3RpbmcgbWFwLicsXG4gICAgICB0YWdzOiBbJ29zaW50JywgJ3N1YmRvbWFpbicsICdhc3NldGZpbmRlciddLFxuICAgICAgZXZpZGVuY2VLZXk6ICdob3N0bmFtZXMnLFxuICAgICAgdmFsdWVzOiBub3JtYWxpemVIb3N0bmFtZUxpbmVzKGxpbmVzKVxuICAgIH0pXG4gIH0sXG4gIHtcbiAgICBpZDogJ2FtYXNzLXBhc3NpdmUnLFxuICAgIG5hbWU6ICdhbWFzcycsXG4gICAgY29tbWFuZDogJ2FtYXNzJyxcbiAgICBidWlsZEFyZ3M6ICh0YXJnZXQpID0+IFsnZW51bScsICctcGFzc2l2ZScsICctbm9yZWN1cnNpdmUnLCAnLW5vYWx0cycsICctZCcsIHRhcmdldF0sXG4gICAgcGFyc2U6IChsaW5lcykgPT4gKHtcbiAgICAgIGNhdGVnb3J5OiAnaG9zdG5hbWUnLFxuICAgICAgdGl0bGU6ICdQYXNzaXZlIGVudW1lcmF0aW9uIHZpYSBhbWFzcycsXG4gICAgICBkZXNjcmlwdGlvbjogJ2FtYXNzIHBhc3NpdmUgbW9kZSByZXR1cm5lZCBwdWJsaWMgaG9zdG5hbWVzIHRoYXQgY2FuIGV4cGFuZCB0aGUgdGVzdGluZyBtYXAuJyxcbiAgICAgIHRhZ3M6IFsnb3NpbnQnLCAnc3ViZG9tYWluJywgJ2FtYXNzJ10sXG4gICAgICBldmlkZW5jZUtleTogJ2hvc3RuYW1lcycsXG4gICAgICB2YWx1ZXM6IG5vcm1hbGl6ZUhvc3RuYW1lTGluZXMobGluZXMpXG4gICAgfSlcbiAgfSxcbiAge1xuICAgIGlkOiAnZ2F1JyxcbiAgICBuYW1lOiAnZ2F1JyxcbiAgICBjb21tYW5kOiAnZ2F1JyxcbiAgICBidWlsZEFyZ3M6ICh0YXJnZXQpID0+IFsnLS1zdWJzJywgdGFyZ2V0XSxcbiAgICBwYXJzZTogKGxpbmVzKSA9PiAoe1xuICAgICAgY2F0ZWdvcnk6ICdhcmNoaXZlLXJlZmVyZW5jZScsXG4gICAgICB0aXRsZTogJ0hpc3RvcmljYWwgVVJMIHJlZmVyZW5jZXMgdmlhIGdhdScsXG4gICAgICBkZXNjcmlwdGlvbjogJ2dhdSByZXR1cm5lZCBhcmNoaXZlZCBvciBpbmRleGVkIFVSTHMgdGhhdCBtYXkgaGVscCBwcmlvcml0aXplIGZvbGxvdy1vbiByZXZpZXcuJyxcbiAgICAgIHRhZ3M6IFsnb3NpbnQnLCAnYXJjaGl2ZScsICdnYXUnXSxcbiAgICAgIGV2aWRlbmNlS2V5OiAndXJscycsXG4gICAgICB2YWx1ZXM6IG5vcm1hbGl6ZVVybExpbmVzKGxpbmVzKVxuICAgIH0pXG4gIH0sXG4gIHtcbiAgICBpZDogJ3dheWJhY2t1cmxzJyxcbiAgICBuYW1lOiAnd2F5YmFja3VybHMnLFxuICAgIGNvbW1hbmQ6ICd3YXliYWNrdXJscycsXG4gICAgYnVpbGRBcmdzOiAodGFyZ2V0KSA9PiBbdGFyZ2V0XSxcbiAgICBwYXJzZTogKGxpbmVzKSA9PiAoe1xuICAgICAgY2F0ZWdvcnk6ICdhcmNoaXZlLXJlZmVyZW5jZScsXG4gICAgICB0aXRsZTogJ0hpc3RvcmljYWwgVVJMIHJlZmVyZW5jZXMgdmlhIHdheWJhY2t1cmxzJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnd2F5YmFja3VybHMgcmV0dXJuZWQgYXJjaGl2ZWQgVVJMcyB0aGF0IG1heSBoZWxwIHByaW9yaXRpemUgZm9sbG93LW9uIHJldmlldy4nLFxuICAgICAgdGFnczogWydvc2ludCcsICdhcmNoaXZlJywgJ3dheWJhY2snXSxcbiAgICAgIGV2aWRlbmNlS2V5OiAndXJscycsXG4gICAgICB2YWx1ZXM6IG5vcm1hbGl6ZVVybExpbmVzKGxpbmVzKVxuICAgIH0pXG4gIH1cbl07XG5cbmV4cG9ydCBjb25zdCBleHRlcm5hbFRvb2xDb2xsZWN0b3JzOiBDb2xsZWN0b3JEZWZpbml0aW9uW10gPSBFWFRFUk5BTF9UT09MX1NQRUNTLm1hcCgoc3BlYykgPT4gKHtcbiAgaWQ6IGBleHRlcm5hbC0ke3NwZWMuaWR9YCxcbiAgbmFtZTogYEV4dGVybmFsIFRvb2w6ICR7c3BlYy5uYW1lfWAsXG4gIGFzeW5jIHJ1bihjb250ZXh0KTogUHJvbWlzZTxDb2xsZWN0b3JSdW5PdXRwdXQ+IHtcbiAgICBjb25zdCBzdGFydGVkQXQgPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCk7XG4gICAgY29uc3Qgd2FybmluZ3M6IEV4cG9ydFdhcm5pbmdbXSA9IFtdO1xuICAgIGNvbnN0IHRhcmdldCA9XG4gICAgICBjb250ZXh0LmFwcGFyZW50Um9vdERvbWFpbiA/P1xuICAgICAgZGVyaXZlQXBwYXJlbnRSb290RG9tYWluKGNvbnRleHQucHJpbWFyeUhvc3RuYW1lKSA/P1xuICAgICAgY29udGV4dC5wcmltYXJ5SG9zdG5hbWU7XG4gICAgY29uc3QgYXJncyA9IHNwZWMuYnVpbGRBcmdzKHRhcmdldCk7XG4gICAgY29uc3QgY29tbWFuZExhYmVsID0gW3NwZWMuY29tbWFuZCwgLi4uYXJnc10uam9pbignICcpO1xuXG4gICAgY29uc3QgcHJvY2Vzc1Jlc3VsdCA9IGF3YWl0IHJ1blByb2Nlc3Moc3BlYy5jb21tYW5kLCBhcmdzLCBjb250ZXh0LnRpbWVvdXRNcyk7XG4gICAgaWYgKHByb2Nlc3NSZXN1bHQuc3RhdHVzID09PSAnbWlzc2luZycpIHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSBgJHtzcGVjLmNvbW1hbmR9IHdhcyBub3QgZm91bmQgb24gUEFUSDsgdGhlIGNvbGxlY3RvciB3YXMgc2tpcHBlZC5gO1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAgdG9vbEV4ZWN1dGlvbjoge1xuICAgICAgICAgIHRvb2xJZDogc3BlYy5pZCxcbiAgICAgICAgICBuYW1lOiBzcGVjLm5hbWUsXG4gICAgICAgICAgbW9kZTogJ2V4dGVybmFsJyxcbiAgICAgICAgICBzdGF0dXM6ICdza2lwcGVkJyxcbiAgICAgICAgICB0YXJnZXQsXG4gICAgICAgICAgc3RhcnRlZEF0LFxuICAgICAgICAgIGZpbmlzaGVkQXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgICBjb21tYW5kOiBjb21tYW5kTGFiZWwsXG4gICAgICAgICAgb3V0cHV0Q291bnQ6IDAsXG4gICAgICAgICAgd2FybmluZ3M6IFttZXNzYWdlXSxcbiAgICAgICAgICBlcnJvcnM6IFtdXG4gICAgICAgIH0sXG4gICAgICAgIGZpbmRpbmdzOiBbXSxcbiAgICAgICAgd2FybmluZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBjb2RlOiAnRVhURVJOQUxfVE9PTF9NSVNTSU5HJyxcbiAgICAgICAgICAgIG1lc3NhZ2UsXG4gICAgICAgICAgICBzZXZlcml0eTogJ2luZm8nLFxuICAgICAgICAgICAgY29udGV4dDoge1xuICAgICAgICAgICAgICB0b29sSWQ6IHNwZWMuaWRcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIF0sXG4gICAgICAgIGVycm9yczogW11cbiAgICAgIH07XG4gICAgfVxuXG4gICAgY29uc3QgcGFyc2VkID0gc3BlYy5wYXJzZShwcm9jZXNzUmVzdWx0LnN0ZG91dC5zcGxpdCgvXFxyP1xcbi8pLmZpbHRlcihCb29sZWFuKSk7XG4gICAgY29uc3QgZmluaXNoZWRBdCA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICBjb25zdCBmaW5kaW5nczogT3NpbnRGaW5kaW5nW10gPVxuICAgICAgcGFyc2VkLnZhbHVlcy5sZW5ndGggPiAwXG4gICAgICAgID8gW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBmaW5kaW5nSWQ6IGNyZWF0ZUlkKCdmaW5kaW5nJyksXG4gICAgICAgICAgICAgIGNhdGVnb3J5OiBwYXJzZWQuY2F0ZWdvcnksXG4gICAgICAgICAgICAgIHRpdGxlOiBwYXJzZWQudGl0bGUsXG4gICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBwYXJzZWQuZGVzY3JpcHRpb24sXG4gICAgICAgICAgICAgIHRhcmdldCxcbiAgICAgICAgICAgICAgY29uZmlkZW5jZTogJ21lZGl1bScsXG4gICAgICAgICAgICAgIHNvdXJjZVRvb2xzOiBbc3BlYy5pZF0sXG4gICAgICAgICAgICAgIHRhZ3M6IHBhcnNlZC50YWdzLFxuICAgICAgICAgICAgICBldmlkZW5jZToge1xuICAgICAgICAgICAgICAgIFtwYXJzZWQuZXZpZGVuY2VLZXldOiBwYXJzZWQudmFsdWVzLnNsaWNlKDAsIDUwMCksXG4gICAgICAgICAgICAgICAgbGluZUNvdW50OiBwYXJzZWQudmFsdWVzLmxlbmd0aCxcbiAgICAgICAgICAgICAgICBjb21tYW5kOiBjb21tYW5kTGFiZWxcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgOiBbXTtcblxuICAgIGlmIChwcm9jZXNzUmVzdWx0LnN0ZGVyci50cmltKCkpIHtcbiAgICAgIHdhcm5pbmdzLnB1c2goe1xuICAgICAgICBjb2RlOiAnRVhURVJOQUxfVE9PTF9TVERFUlInLFxuICAgICAgICBtZXNzYWdlOiBgJHtzcGVjLmNvbW1hbmR9IGVtaXR0ZWQgc3RkZXJyIG91dHB1dCBkdXJpbmcgcGFzc2l2ZSBjb2xsZWN0aW9uLmAsXG4gICAgICAgIHNldmVyaXR5OiAnaW5mbycsXG4gICAgICAgIGNvbnRleHQ6IHtcbiAgICAgICAgICB0b29sSWQ6IHNwZWMuaWQsXG4gICAgICAgICAgc3RkZXJyOiBwcm9jZXNzUmVzdWx0LnN0ZGVyci5zbGljZSgwLCA4MDApXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGNvbnN0IGVycm9ycyA9IHByb2Nlc3NSZXN1bHQuc3RhdHVzID09PSAnZmFpbGVkJyA/IFtwcm9jZXNzUmVzdWx0LmVycm9yTWVzc2FnZV0gOiBbXTtcbiAgICByZXR1cm4ge1xuICAgICAgdG9vbEV4ZWN1dGlvbjoge1xuICAgICAgICB0b29sSWQ6IHNwZWMuaWQsXG4gICAgICAgIG5hbWU6IHNwZWMubmFtZSxcbiAgICAgICAgbW9kZTogJ2V4dGVybmFsJyxcbiAgICAgICAgc3RhdHVzOlxuICAgICAgICAgIHByb2Nlc3NSZXN1bHQuc3RhdHVzID09PSAnZmFpbGVkJ1xuICAgICAgICAgICAgPyBmaW5kaW5ncy5sZW5ndGggPiAwXG4gICAgICAgICAgICAgID8gJ3BhcnRpYWwnXG4gICAgICAgICAgICAgIDogJ2ZhaWxlZCdcbiAgICAgICAgICAgIDogJ2NvbXBsZXRlZCcsXG4gICAgICAgIHRhcmdldCxcbiAgICAgICAgc3RhcnRlZEF0LFxuICAgICAgICBmaW5pc2hlZEF0LFxuICAgICAgICBjb21tYW5kOiBjb21tYW5kTGFiZWwsXG4gICAgICAgIG91dHB1dENvdW50OiBwYXJzZWQudmFsdWVzLmxlbmd0aCxcbiAgICAgICAgd2FybmluZ3M6IHdhcm5pbmdzLm1hcCgod2FybmluZykgPT4gd2FybmluZy5tZXNzYWdlKSxcbiAgICAgICAgZXJyb3JzXG4gICAgICB9LFxuICAgICAgZmluZGluZ3MsXG4gICAgICB3YXJuaW5ncyxcbiAgICAgIGVycm9yczogZXJyb3JzLm1hcCgobWVzc2FnZSkgPT4gKHtcbiAgICAgICAgY29kZTogJ0VYVEVSTkFMX1RPT0xfRkFJTEVEJyxcbiAgICAgICAgbWVzc2FnZSxcbiAgICAgICAgcmVjb3ZlcmFibGU6IHRydWUsXG4gICAgICAgIGNvbnRleHQ6IHtcbiAgICAgICAgICB0b29sSWQ6IHNwZWMuaWRcbiAgICAgICAgfVxuICAgICAgfSkpXG4gICAgfTtcbiAgfVxufSkpO1xuXG50eXBlIFByb2Nlc3NSdW5SZXN1bHQgPVxuICB8IHtcbiAgICAgIHN0YXR1czogJ2NvbXBsZXRlZCc7XG4gICAgICBzdGRvdXQ6IHN0cmluZztcbiAgICAgIHN0ZGVycjogc3RyaW5nO1xuICAgICAgZXJyb3JNZXNzYWdlOiAnJztcbiAgICB9XG4gIHwge1xuICAgICAgc3RhdHVzOiAnZmFpbGVkJztcbiAgICAgIHN0ZG91dDogc3RyaW5nO1xuICAgICAgc3RkZXJyOiBzdHJpbmc7XG4gICAgICBlcnJvck1lc3NhZ2U6IHN0cmluZztcbiAgICB9XG4gIHwge1xuICAgICAgc3RhdHVzOiAnbWlzc2luZyc7XG4gICAgICBzdGRvdXQ6ICcnO1xuICAgICAgc3RkZXJyOiAnJztcbiAgICAgIGVycm9yTWVzc2FnZTogJyc7XG4gICAgfTtcblxuZnVuY3Rpb24gcnVuUHJvY2Vzcyhjb21tYW5kOiBzdHJpbmcsIGFyZ3M6IHN0cmluZ1tdLCB0aW1lb3V0TXM6IG51bWJlcik6IFByb21pc2U8UHJvY2Vzc1J1blJlc3VsdD4ge1xuICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUpID0+IHtcbiAgICBjb25zdCBjaGlsZCA9IHNwYXduKGNvbW1hbmQsIGFyZ3MsIHtcbiAgICAgIHN0ZGlvOiBbJ2lnbm9yZScsICdwaXBlJywgJ3BpcGUnXVxuICAgIH0pO1xuXG4gICAgbGV0IHN0ZG91dCA9ICcnO1xuICAgIGxldCBzdGRlcnIgPSAnJztcbiAgICBsZXQgc2V0dGxlZCA9IGZhbHNlO1xuICAgIGNvbnN0IHRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIGlmICghc2V0dGxlZCkge1xuICAgICAgICBzZXR0bGVkID0gdHJ1ZTtcbiAgICAgICAgY2hpbGQua2lsbCgpO1xuICAgICAgICByZXNvbHZlKHtcbiAgICAgICAgICBzdGF0dXM6ICdmYWlsZWQnLFxuICAgICAgICAgIHN0ZG91dCxcbiAgICAgICAgICBzdGRlcnIsXG4gICAgICAgICAgZXJyb3JNZXNzYWdlOiBgdGltZWQgb3V0IGFmdGVyICR7dGltZW91dE1zfW1zYFxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9LCB0aW1lb3V0TXMpO1xuXG4gICAgY2hpbGQuc3Rkb3V0Lm9uKCdkYXRhJywgKGNodW5rKSA9PiB7XG4gICAgICBzdGRvdXQgKz0gU3RyaW5nKGNodW5rKTtcbiAgICB9KTtcbiAgICBjaGlsZC5zdGRlcnIub24oJ2RhdGEnLCAoY2h1bmspID0+IHtcbiAgICAgIHN0ZGVyciArPSBTdHJpbmcoY2h1bmspO1xuICAgIH0pO1xuICAgIGNoaWxkLm9uKCdlcnJvcicsIChlcnJvcikgPT4ge1xuICAgICAgY2xlYXJUaW1lb3V0KHRpbWVvdXQpO1xuICAgICAgaWYgKHNldHRsZWQpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgc2V0dGxlZCA9IHRydWU7XG4gICAgICBpZiAoJ2NvZGUnIGluIGVycm9yICYmIGVycm9yLmNvZGUgPT09ICdFTk9FTlQnKSB7XG4gICAgICAgIHJlc29sdmUoe1xuICAgICAgICAgIHN0YXR1czogJ21pc3NpbmcnLFxuICAgICAgICAgIHN0ZG91dDogJycsXG4gICAgICAgICAgc3RkZXJyOiAnJyxcbiAgICAgICAgICBlcnJvck1lc3NhZ2U6ICcnXG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIHJlc29sdmUoe1xuICAgICAgICBzdGF0dXM6ICdmYWlsZWQnLFxuICAgICAgICBzdGRvdXQsXG4gICAgICAgIHN0ZGVycixcbiAgICAgICAgZXJyb3JNZXNzYWdlOiBlcnJvci5tZXNzYWdlXG4gICAgICB9KTtcbiAgICB9KTtcbiAgICBjaGlsZC5vbignY2xvc2UnLCAoY29kZSkgPT4ge1xuICAgICAgY2xlYXJUaW1lb3V0KHRpbWVvdXQpO1xuICAgICAgaWYgKHNldHRsZWQpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgc2V0dGxlZCA9IHRydWU7XG4gICAgICBpZiAoY29kZSA9PSAwKSB7XG4gICAgICAgIHJlc29sdmUoe1xuICAgICAgICAgIHN0YXR1czogJ2NvbXBsZXRlZCcsXG4gICAgICAgICAgc3Rkb3V0LFxuICAgICAgICAgIHN0ZGVycixcbiAgICAgICAgICBlcnJvck1lc3NhZ2U6ICcnXG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIHJlc29sdmUoe1xuICAgICAgICBzdGF0dXM6ICdmYWlsZWQnLFxuICAgICAgICBzdGRvdXQsXG4gICAgICAgIHN0ZGVycixcbiAgICAgICAgZXJyb3JNZXNzYWdlOiBgZXhpdGVkIHdpdGggY29kZSAke2NvZGUgPz8gJ3Vua25vd24nfWBcbiAgICAgIH0pO1xuICAgIH0pO1xuICB9KTtcbn1cblxuZnVuY3Rpb24gbm9ybWFsaXplSG9zdG5hbWVMaW5lcyhsaW5lczogc3RyaW5nW10pOiBzdHJpbmdbXSB7XG4gIGNvbnN0IGhvc3RuYW1lcyA9IG5ldyBTZXQ8c3RyaW5nPigpO1xuICBmb3IgKGNvbnN0IGxpbmUgb2YgbGluZXMpIHtcbiAgICBjb25zdCBub3JtYWxpemVkID0gbm9ybWFsaXplSG9zdG5hbWUobGluZSk7XG4gICAgaWYgKG5vcm1hbGl6ZWQpIHtcbiAgICAgIGhvc3RuYW1lcy5hZGQobm9ybWFsaXplZCk7XG4gICAgfVxuICB9XG4gIHJldHVybiBbLi4uaG9zdG5hbWVzXS5zb3J0KCk7XG59XG5cbmZ1bmN0aW9uIG5vcm1hbGl6ZVVybExpbmVzKGxpbmVzOiBzdHJpbmdbXSk6IHN0cmluZ1tdIHtcbiAgY29uc3QgdXJscyA9IG5ldyBTZXQ8c3RyaW5nPigpO1xuICBmb3IgKGNvbnN0IGxpbmUgb2YgbGluZXMpIHtcbiAgICBjb25zdCB2YWx1ZSA9IGxpbmUudHJpbSgpO1xuICAgIGlmICghdmFsdWUpIHtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cblxuICAgIHRyeSB7XG4gICAgICB1cmxzLmFkZChuZXcgVVJMKHZhbHVlKS50b1N0cmluZygpKTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgfVxuICByZXR1cm4gWy4uLnVybHNdLnNvcnQoKTtcbn1cblxuZnVuY3Rpb24gY3JlYXRlSWQocHJlZml4OiBzdHJpbmcpOiBzdHJpbmcge1xuICByZXR1cm4gYCR7cHJlZml4fV8ke0RhdGUubm93KCkudG9TdHJpbmcoMzYpfV8ke2NyeXB0by5yYW5kb21VVUlEKCl9YDtcbn1cbiIsICJleHBvcnQgY29uc3QgQkxBTkNIRV9TQ0hFTUFfVkVSU0lPTiA9ICcxLjEuMCcgYXMgY29uc3Q7XG5leHBvcnQgY29uc3QgQkxBTkNIRV9FWFBPUlRfS0lORCA9ICdibGFuY2hlLmV4cG9ydCcgYXMgY29uc3Q7XG5leHBvcnQgY29uc3QgQkxBTkNIRV9UUkFGRklDX0xFREdFUl9TQ0hFTUFfVkVSU0lPTiA9ICcxLjAuMCcgYXMgY29uc3Q7XG5leHBvcnQgY29uc3QgQkxBTkNIRV9UUkFGRklDX0xFREdFUl9LSU5EID0gJ2JsYW5jaGUudHJhZmZpYy1sZWRnZXInIGFzIGNvbnN0O1xuZXhwb3J0IGNvbnN0IEJMQU5DSEVfT1NJTlRfU0NIRU1BX1ZFUlNJT04gPSAnMS4wLjAnIGFzIGNvbnN0O1xuZXhwb3J0IGNvbnN0IEJMQU5DSEVfT1NJTlRfU0VFRF9LSU5EID0gJ2JsYW5jaGUub3NpbnQtc2VlZCcgYXMgY29uc3Q7XG5leHBvcnQgY29uc3QgQkxBTkNIRV9PU0lOVF9SRVBPUlRfS0lORCA9ICdibGFuY2hlLm9zaW50LXJlcG9ydCcgYXMgY29uc3Q7XG5leHBvcnQgY29uc3QgQkxBTkNIRV9URUFSX1NIRUVUX1NDSEVNQV9WRVJTSU9OID0gJzEuMC4wJyBhcyBjb25zdDtcbmV4cG9ydCBjb25zdCBCTEFOQ0hFX1RFQVJfU0hFRVRfS0lORCA9ICdibGFuY2hlLnRlYXItc2hlZXQnIGFzIGNvbnN0O1xuIiwgImltcG9ydCB0eXBlIHsgT3NpbnRTY29wZVN0YXRlbWVudCB9IGZyb20gJy4uLy4uLy4uL3NoYXJlZC1zY2hlbWEvc3JjJztcblxuY29uc3QgQUxMT1dFRF9BQ1RJVklUSUVTID0gW1xuICAnUmVzb2x2ZSBwdWJsaWMgRE5TIHJlY29yZHMgZm9yIGluLXNjb3BlIGhvc3RzLicsXG4gICdGZXRjaCBwdWJsaWMgd2ViIHJlc291cmNlcyBzdWNoIGFzIC8sIHJvYm90cy50eHQsIHNpdGVtYXAueG1sLCBhbmQgLy53ZWxsLWtub3duL3NlY3VyaXR5LnR4dC4nLFxuICAnSW5zcGVjdCBwdWJsaWMgVExTIGNlcnRpZmljYXRlIG1ldGFkYXRhIHByZXNlbnRlZCBieSB0aGUgdGFyZ2V0IGhvc3QuJyxcbiAgJ1J1biBhcHByb3ZlZCBwYXNzaXZlIE9TSU5UIHRvb2xzIHdpdGggbm9uLWludHJ1c2l2ZSBkaXNjb3ZlcnkgZmxhZ3Mgb25seS4nXG5dIGFzIGNvbnN0O1xuXG5jb25zdCBESVNBTExPV0VEX0FDVElWSVRJRVMgPSBbXG4gICdEbyBub3QgYXV0aGVudGljYXRlLCBicnV0ZSBmb3JjZSwgZnV6eiwgZXhwbG9pdCwgc2NhbiBwb3J0cyBicm9hZGx5LCBvciB2YWxpZGF0ZSB2dWxuZXJhYmlsaXRpZXMuJyxcbiAgJ0RvIG5vdCBjb2xsZWN0IG5vbi1wdWJsaWMgaW5mb3JtYXRpb24gb3IgYnlwYXNzIGFjY2VzcyBjb250cm9scy4nLFxuICAnRG8gbm90IGFzc2lnbiBzZXZlcml0eSBvciByZXByZXNlbnQgaW5mb3JtYXRpb25hbCBPU0lOVCBhcyB2YWxpZGF0ZWQgZmluZGluZ3MuJyxcbiAgJ0RvIG5vdCByZXBsYWNlIGV4aXN0aW5nIFByb2RQVCB0ZXN0aW5nIHdvcmtmbG93czsgdGhpcyBvdXRwdXQgaXMgcHJlcGFyYXRvcnkgY29udGV4dC4nXG5dIGFzIGNvbnN0O1xuXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlRGVmYXVsdFNjb3BlU3RhdGVtZW50KCk6IE9zaW50U2NvcGVTdGF0ZW1lbnQge1xuICByZXR1cm4ge1xuICAgIG1vZGU6ICdwdWJsaWMtcGFzc2l2ZScsXG4gICAgYWxsb3dlZEFjdGl2aXRpZXM6IFsuLi5BTExPV0VEX0FDVElWSVRJRVNdLFxuICAgIGRpc2FsbG93ZWRBY3Rpdml0aWVzOiBbLi4uRElTQUxMT1dFRF9BQ1RJVklUSUVTXSxcbiAgICBvcGVyYXRvck5vdGVzOiBbXG4gICAgICAnT3V0cHV0cyBhcmUgaW5mb3JtYXRpb25hbCBhbmQgaW50ZW5kZWQgdG8gZ3VpZGUgZm9sbG93LW9uIHRlc3RpbmcsIG5vdCB2YWxpZGF0ZSBzZWN1cml0eSBpbXBhY3QuJ1xuICAgIF1cbiAgfTtcbn1cbiIsICJpbXBvcnQge1xuICBCTEFOQ0hFX09TSU5UX1NDSEVNQV9WRVJTSU9OLFxuICBCTEFOQ0hFX09TSU5UX1NFRURfS0lORCxcbiAgdHlwZSBCbGFuY2hlT3NpbnRTZWVkVjEsXG4gIHR5cGUgT3NpbnRTZWVkT2JzZXJ2YXRpb24sXG4gIHR5cGUgT3NpbnRTZWVkU291cmNlVHlwZVxufSBmcm9tICcuLi8uLi8uLi9zaGFyZWQtc2NoZW1hL3NyYyc7XG5pbXBvcnQgeyBjcmVhdGVEZWZhdWx0U2NvcGVTdGF0ZW1lbnQgfSBmcm9tICcuL2d1YXJkcmFpbHMnO1xuXG5leHBvcnQgaW50ZXJmYWNlIE5vcm1hbGl6ZWRUYXJnZXQge1xuICBwcmltYXJ5SG9zdG5hbWU6IHN0cmluZztcbiAgYXBwYXJlbnRSb290RG9tYWluPzogc3RyaW5nO1xuICB0YXJnZXRVcmw/OiBzdHJpbmc7XG4gIHRhcmdldE9yaWdpbj86IHN0cmluZztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIG5vcm1hbGl6ZUhvc3RuYW1lKHJhd1ZhbHVlOiBzdHJpbmcgfCB1bmRlZmluZWQpOiBzdHJpbmcgfCB1bmRlZmluZWQge1xuICBpZiAoIXJhd1ZhbHVlKSB7XG4gICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgfVxuXG4gIGNvbnN0IG5vcm1hbGl6ZWQgPSByYXdWYWx1ZS50cmltKCkudG9Mb3dlckNhc2UoKS5yZXBsYWNlKC9cXC4kLywgJycpO1xuICBpZiAoIW5vcm1hbGl6ZWQgfHwgL1xccy8udGVzdChub3JtYWxpemVkKSkge1xuICAgIHJldHVybiB1bmRlZmluZWQ7XG4gIH1cblxuICByZXR1cm4gbm9ybWFsaXplZDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGRlcml2ZUFwcGFyZW50Um9vdERvbWFpbihob3N0bmFtZTogc3RyaW5nIHwgdW5kZWZpbmVkKTogc3RyaW5nIHwgdW5kZWZpbmVkIHtcbiAgY29uc3Qgbm9ybWFsaXplZCA9IG5vcm1hbGl6ZUhvc3RuYW1lKGhvc3RuYW1lKTtcbiAgaWYgKCFub3JtYWxpemVkKSB7XG4gICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgfVxuXG4gIGNvbnN0IGxhYmVscyA9IG5vcm1hbGl6ZWQuc3BsaXQoJy4nKTtcbiAgaWYgKGxhYmVscy5sZW5ndGggPD0gMikge1xuICAgIHJldHVybiBub3JtYWxpemVkO1xuICB9XG5cbiAgY29uc3QgdGxkID0gbGFiZWxzLmF0KC0xKSA/PyAnJztcbiAgY29uc3Qgc2Vjb25kTGV2ZWwgPSBsYWJlbHMuYXQoLTIpID8/ICcnO1xuICBjb25zdCBjb21tb25Db3VudHJ5Q29kZVNlY29uZExldmVscyA9IG5ldyBTZXQoWydjbycsICdjb20nLCAnb3JnJywgJ25ldCcsICdnb3YnLCAnZWR1J10pO1xuICBpZiAodGxkLmxlbmd0aCA9PT0gMiAmJiBjb21tb25Db3VudHJ5Q29kZVNlY29uZExldmVscy5oYXMoc2Vjb25kTGV2ZWwpICYmIGxhYmVscy5sZW5ndGggPj0gMykge1xuICAgIHJldHVybiBsYWJlbHMuc2xpY2UoLTMpLmpvaW4oJy4nKTtcbiAgfVxuXG4gIHJldHVybiBsYWJlbHMuc2xpY2UoLTIpLmpvaW4oJy4nKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIG5vcm1hbGl6ZVNlZWQoc2VlZDogQmxhbmNoZU9zaW50U2VlZFYxKTogTm9ybWFsaXplZFRhcmdldCB7XG4gIHJldHVybiB7XG4gICAgcHJpbWFyeUhvc3RuYW1lOiBzZWVkLnNlZWQucHJpbWFyeUhvc3RuYW1lLFxuICAgIGFwcGFyZW50Um9vdERvbWFpbjogc2VlZC5zZWVkLmFwcGFyZW50Um9vdERvbWFpbixcbiAgICB0YXJnZXRVcmw6IHNlZWQuc2VlZC50YXJnZXRVcmwsXG4gICAgdGFyZ2V0T3JpZ2luOiBzZWVkLnNlZWQudGFyZ2V0T3JpZ2luXG4gIH07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBleHRyYWN0UmVsYXRlZEhvc3RuYW1lcyhzZWVkOiBCbGFuY2hlT3NpbnRTZWVkVjEpOiBzdHJpbmdbXSB7XG4gIGNvbnN0IGhvc3RuYW1lcyA9IG5ldyBTZXQ8c3RyaW5nPigpO1xuICBmb3IgKGNvbnN0IHJlbGF0ZWRIb3N0IG9mIHNlZWQuYnJvd3NlckNvbnRleHQucmVsYXRlZEhvc3RzKSB7XG4gICAgY29uc3Qgbm9ybWFsaXplZCA9IG5vcm1hbGl6ZUhvc3RuYW1lKHJlbGF0ZWRIb3N0Lmhvc3RuYW1lKTtcbiAgICBpZiAobm9ybWFsaXplZCkge1xuICAgICAgaG9zdG5hbWVzLmFkZChub3JtYWxpemVkKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gWy4uLmhvc3RuYW1lc10uc29ydCgpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlTWFudWFsU2VlZChyYXdUYXJnZXQ6IHN0cmluZyk6IEJsYW5jaGVPc2ludFNlZWRWMSB7XG4gIGNvbnN0IHRhcmdldFVybCA9IGVuc3VyZVVybChyYXdUYXJnZXQpO1xuICBjb25zdCBwYXJzZWQgPSBuZXcgVVJMKHRhcmdldFVybCk7XG4gIGNvbnN0IHByaW1hcnlIb3N0bmFtZSA9IG5vcm1hbGl6ZUhvc3RuYW1lKHBhcnNlZC5ob3N0bmFtZSk7XG4gIGlmICghcHJpbWFyeUhvc3RuYW1lKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBVbmFibGUgdG8gZGVyaXZlIGEgaG9zdG5hbWUgZnJvbSB0YXJnZXQgJHtyYXdUYXJnZXR9YCk7XG4gIH1cblxuICByZXR1cm4ge1xuICAgIGtpbmQ6IEJMQU5DSEVfT1NJTlRfU0VFRF9LSU5ELFxuICAgIHNjaGVtYVZlcnNpb246IEJMQU5DSEVfT1NJTlRfU0NIRU1BX1ZFUlNJT04sXG4gICAgc2VlZE1ldGFkYXRhOiB7XG4gICAgICBzZWVkSWQ6IGNyZWF0ZUlkKCdzZWVkJyksXG4gICAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcbiAgICAgIGdlbmVyYXRlZEJ5OiB7XG4gICAgICAgIHByb2R1Y3Q6ICdCTEFOQ0hFJyxcbiAgICAgICAgY29tcG9uZW50OiAnb3NpbnQtb3JjaGVzdHJhdG9yL2NsaScsXG4gICAgICAgIHZlcnNpb246ICcwLjEuMCdcbiAgICAgIH1cbiAgICB9LFxuICAgIHNjb3BlOiBjcmVhdGVEZWZhdWx0U2NvcGVTdGF0ZW1lbnQoKSxcbiAgICBzZWVkOiB7XG4gICAgICB0YXJnZXRVcmwsXG4gICAgICB0YXJnZXRPcmlnaW46IHBhcnNlZC5vcmlnaW4sXG4gICAgICBwcmltYXJ5SG9zdG5hbWUsXG4gICAgICBhcHBhcmVudFJvb3REb21haW46IGRlcml2ZUFwcGFyZW50Um9vdERvbWFpbihwcmltYXJ5SG9zdG5hbWUpLFxuICAgICAgc291cmNlVHlwZTogJ21hbnVhbCdcbiAgICB9LFxuICAgIGJyb3dzZXJDb250ZXh0OiB7XG4gICAgICBwYWdlVXJsOiB0YXJnZXRVcmwsXG4gICAgICBwYWdlT3JpZ2luOiBwYXJzZWQub3JpZ2luLFxuICAgICAgYXBwYXJlbnRSb290RG9tYWluOiBkZXJpdmVBcHBhcmVudFJvb3REb21haW4ocHJpbWFyeUhvc3RuYW1lKSxcbiAgICAgIHJlbGF0ZWRIb3N0czogW10sXG4gICAgICBzaWduYWxzOiB7fVxuICAgIH0sXG4gICAgd2FybmluZ3M6IFtcbiAgICAgIHtcbiAgICAgICAgY29kZTogJ01BTlVBTF9TRUVEX0NSRUFURUQnLFxuICAgICAgICBtZXNzYWdlOiAnVGhlIE9TSU5UIHJ1biB1c2VkIGEgbWFudWFsbHkgcHJvdmlkZWQgdGFyZ2V0IGluc3RlYWQgb2YgYSBDaHJvbWl1bS1kZXJpdmVkIHNlZWQuJyxcbiAgICAgICAgc2V2ZXJpdHk6ICdpbmZvJ1xuICAgICAgfVxuICAgIF1cbiAgfTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGNyZWF0ZVNlZWRPYnNlcnZhdGlvbihcbiAgaG9zdG5hbWU6IHN0cmluZyxcbiAgc291cmNlVHlwZTogT3NpbnRTZWVkU291cmNlVHlwZSxcbiAgaW5wdXQ6IHtcbiAgICB1cmw/OiBzdHJpbmc7XG4gICAgY29uZmlkZW5jZT86IE9zaW50U2VlZE9ic2VydmF0aW9uWydjb25maWRlbmNlJ107XG4gICAgbm90ZT86IHN0cmluZztcbiAgfSA9IHt9XG4pOiBPc2ludFNlZWRPYnNlcnZhdGlvbiB7XG4gIHJldHVybiB7XG4gICAgaG9zdG5hbWUsXG4gICAgc291cmNlVHlwZSxcbiAgICBjb25maWRlbmNlOiBpbnB1dC5jb25maWRlbmNlID8/ICdtZWRpdW0nLFxuICAgIHVybDogaW5wdXQudXJsLFxuICAgIG5vdGU6IGlucHV0Lm5vdGVcbiAgfTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGVuc3VyZVVybChyYXdUYXJnZXQ6IHN0cmluZyk6IHN0cmluZyB7XG4gIGlmICgvXlthLXpdKzpcXC9cXC8vaS50ZXN0KHJhd1RhcmdldCkpIHtcbiAgICByZXR1cm4gcmF3VGFyZ2V0O1xuICB9XG5cbiAgcmV0dXJuIGBodHRwczovLyR7cmF3VGFyZ2V0fWA7XG59XG5cbmZ1bmN0aW9uIGNyZWF0ZUlkKHByZWZpeDogc3RyaW5nKTogc3RyaW5nIHtcbiAgcmV0dXJuIGAke3ByZWZpeH1fJHtEYXRlLm5vdygpLnRvU3RyaW5nKDM2KX1fJHtjcnlwdG8ucmFuZG9tVVVJRCgpfWA7XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBFeHBvcnRXYXJuaW5nLCBPc2ludEZpbmRpbmcgfSBmcm9tICcuLi8uLi8uLi9zaGFyZWQtc2NoZW1hL3NyYyc7XG5pbXBvcnQgdHlwZSB7IENvbGxlY3RvckRlZmluaXRpb24sIENvbGxlY3RvclJ1bk91dHB1dCB9IGZyb20gJy4vdHlwZXMnO1xuXG5pbnRlcmZhY2UgRmV0Y2hSZXN1bHQge1xuICB1cmw6IHN0cmluZztcbiAgb2s6IGJvb2xlYW47XG4gIHN0YXR1czogbnVtYmVyO1xuICBoZWFkZXJzOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+O1xuICBib2R5OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBjb25zdCBodHRwQ29sbGVjdG9yOiBDb2xsZWN0b3JEZWZpbml0aW9uID0ge1xuICBpZDogJ2J1aWx0aW4taHR0cCcsXG4gIG5hbWU6ICdCdWlsdC1pbiBIVFRQIFN1cmZhY2UgQ29sbGVjdG9yJyxcbiAgYXN5bmMgcnVuKGNvbnRleHQpOiBQcm9taXNlPENvbGxlY3RvclJ1bk91dHB1dD4ge1xuICAgIGNvbnN0IHN0YXJ0ZWRBdCA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICBjb25zdCB3YXJuaW5nczogRXhwb3J0V2FybmluZ1tdID0gW107XG4gICAgY29uc3QgZmluZGluZ3M6IE9zaW50RmluZGluZ1tdID0gW107XG4gICAgY29uc3QgZXJyb3JzOiBzdHJpbmdbXSA9IFtdO1xuXG4gICAgY29uc3QgYmFzZUNhbmRpZGF0ZXMgPSBbYGh0dHBzOi8vJHtjb250ZXh0LnByaW1hcnlIb3N0bmFtZX1gLCBgaHR0cDovLyR7Y29udGV4dC5wcmltYXJ5SG9zdG5hbWV9YF07XG4gICAgY29uc3QgaG9tZXBhZ2UgPSBhd2FpdCBmaXJzdFN1Y2Nlc3NmdWxGZXRjaChiYXNlQ2FuZGlkYXRlcywgJy8nLCBjb250ZXh0LnRpbWVvdXRNcyk7XG4gICAgaWYgKGhvbWVwYWdlKSB7XG4gICAgICBmaW5kaW5ncy5wdXNoKGJ1aWxkSG9tZXBhZ2VGaW5kaW5nKGhvbWVwYWdlKSk7XG5cbiAgICAgIGNvbnN0IHRlY2hFdmlkZW5jZSA9IGV4dHJhY3RUZWNobm9sb2d5RXZpZGVuY2UoaG9tZXBhZ2UpO1xuICAgICAgaWYgKE9iamVjdC5rZXlzKHRlY2hFdmlkZW5jZSkubGVuZ3RoID4gMCkge1xuICAgICAgICBmaW5kaW5ncy5wdXNoKHtcbiAgICAgICAgICBmaW5kaW5nSWQ6IGNyZWF0ZUlkKCdmaW5kaW5nJyksXG4gICAgICAgICAgY2F0ZWdvcnk6ICd0ZWNobm9sb2d5LWhpbnQnLFxuICAgICAgICAgIHRpdGxlOiBgUHVibGljIHRlY2hub2xvZ3kgaGludHMgZm9yICR7Y29udGV4dC5wcmltYXJ5SG9zdG5hbWV9YCxcbiAgICAgICAgICBkZXNjcmlwdGlvbjpcbiAgICAgICAgICAgICdUaGUgcHVibGljIGxhbmRpbmcgcGFnZSBleHBvc2VkIHJlc3BvbnNlIGhlYWRlcnMgb3IgSFRNTCBtZXRhZGF0YSB0aGF0IGNhbiBndWlkZSBmb2xsb3ctb24gcmV2aWV3LicsXG4gICAgICAgICAgdGFyZ2V0OiBjb250ZXh0LnByaW1hcnlIb3N0bmFtZSxcbiAgICAgICAgICBjb25maWRlbmNlOiAnbWVkaXVtJyxcbiAgICAgICAgICBzb3VyY2VUb29sczogWydidWlsdGluLWh0dHAnXSxcbiAgICAgICAgICB0YWdzOiBbJ2h0dHAnLCAndGVjaG5vbG9neSddLFxuICAgICAgICAgIGV2aWRlbmNlOiB0ZWNoRXZpZGVuY2VcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIHdhcm5pbmdzLnB1c2goe1xuICAgICAgICBjb2RlOiAnSFRUUF9IT01FUEFHRV9VTlJFQUNIQUJMRScsXG4gICAgICAgIG1lc3NhZ2U6IGBUaGUgY29sbGVjdG9yIGNvdWxkIG5vdCByZXRyaWV2ZSBhIHB1YmxpYyBob21lcGFnZSBmb3IgJHtjb250ZXh0LnByaW1hcnlIb3N0bmFtZX0uYCxcbiAgICAgICAgc2V2ZXJpdHk6ICd3YXJuaW5nJ1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgY29uc3QgcHJvYmVCYXNlID0gaG9tZXBhZ2U/LnVybC5yZXBsYWNlKC9cXC8kLywgJycpID8/IGBodHRwczovLyR7Y29udGV4dC5wcmltYXJ5SG9zdG5hbWV9YDtcbiAgICBjb25zdCByb2JvdHMgPSBhd2FpdCBmZXRjaFRleHQoYCR7cHJvYmVCYXNlfS9yb2JvdHMudHh0YCwgY29udGV4dC50aW1lb3V0TXMpO1xuICAgIGlmIChyb2JvdHMub2spIHtcbiAgICAgIGZpbmRpbmdzLnB1c2goYnVpbGRSb2JvdHNGaW5kaW5nKGNvbnRleHQucHJpbWFyeUhvc3RuYW1lLCByb2JvdHMpKTtcbiAgICB9IGVsc2Uge1xuICAgICAgd2FybmluZ3MucHVzaCh7XG4gICAgICAgIGNvZGU6ICdST0JPVFNfVU5BVkFJTEFCTEUnLFxuICAgICAgICBtZXNzYWdlOiBgcm9ib3RzLnR4dCB3YXMgbm90IHB1YmxpY2x5IGF2YWlsYWJsZSBhdCAke3Byb2JlQmFzZX0vcm9ib3RzLnR4dC5gLFxuICAgICAgICBzZXZlcml0eTogJ2luZm8nXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBjb25zdCBzZWN1cml0eVR4dCA9IGF3YWl0IGZldGNoVGV4dChgJHtwcm9iZUJhc2V9Ly53ZWxsLWtub3duL3NlY3VyaXR5LnR4dGAsIGNvbnRleHQudGltZW91dE1zKTtcbiAgICBpZiAoc2VjdXJpdHlUeHQub2spIHtcbiAgICAgIGZpbmRpbmdzLnB1c2goYnVpbGRTZWN1cml0eVR4dEZpbmRpbmcoY29udGV4dC5wcmltYXJ5SG9zdG5hbWUsIHNlY3VyaXR5VHh0KSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHdhcm5pbmdzLnB1c2goe1xuICAgICAgICBjb2RlOiAnU0VDVVJJVFlfVFhUX1VOQVZBSUxBQkxFJyxcbiAgICAgICAgbWVzc2FnZTogYHNlY3VyaXR5LnR4dCB3YXMgbm90IHB1YmxpY2x5IGF2YWlsYWJsZSBhdCAke3Byb2JlQmFzZX0vLndlbGwta25vd24vc2VjdXJpdHkudHh0LmAsXG4gICAgICAgIHNldmVyaXR5OiAnaW5mbydcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGNvbnN0IHNpdGVtYXAgPSBhd2FpdCBmZXRjaFRleHQoYCR7cHJvYmVCYXNlfS9zaXRlbWFwLnhtbGAsIGNvbnRleHQudGltZW91dE1zKTtcbiAgICBpZiAoc2l0ZW1hcC5vaykge1xuICAgICAgZmluZGluZ3MucHVzaCh7XG4gICAgICAgIGZpbmRpbmdJZDogY3JlYXRlSWQoJ2ZpbmRpbmcnKSxcbiAgICAgICAgY2F0ZWdvcnk6ICdkb2N1bWVudC1yZWZlcmVuY2UnLFxuICAgICAgICB0aXRsZTogYFB1YmxpYyBzaXRlbWFwIHJlZmVyZW5jZSBmb3IgJHtjb250ZXh0LnByaW1hcnlIb3N0bmFtZX1gLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ0EgcHVibGljIHNpdGVtYXAgd2FzIGRpc2NvdmVyYWJsZSBhbmQgY2FuIGJlIHVzZWQgdG8gd2lkZW4gcGFnZS1sZXZlbCBPU0lOVCByZXZpZXcuJyxcbiAgICAgICAgdGFyZ2V0OiBjb250ZXh0LnByaW1hcnlIb3N0bmFtZSxcbiAgICAgICAgY29uZmlkZW5jZTogJ2hpZ2gnLFxuICAgICAgICBzb3VyY2VUb29sczogWydidWlsdGluLWh0dHAnXSxcbiAgICAgICAgdGFnczogWydodHRwJywgJ3NpdGVtYXAnXSxcbiAgICAgICAgZXZpZGVuY2U6IHtcbiAgICAgICAgICB1cmw6IHNpdGVtYXAudXJsLFxuICAgICAgICAgIHN0YXR1czogc2l0ZW1hcC5zdGF0dXMsXG4gICAgICAgICAgc25pcHBldDogc2l0ZW1hcC5ib2R5LnNsaWNlKDAsIDEyMDApXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGNvbnN0IGZpbmlzaGVkQXQgPSBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCk7XG4gICAgcmV0dXJuIHtcbiAgICAgIHRvb2xFeGVjdXRpb246IHtcbiAgICAgICAgdG9vbElkOiAnYnVpbHRpbi1odHRwJyxcbiAgICAgICAgbmFtZTogJ0J1aWx0LWluIEhUVFAgU3VyZmFjZSBDb2xsZWN0b3InLFxuICAgICAgICBtb2RlOiAnYnVpbHRpbicsXG4gICAgICAgIHN0YXR1czogZXJyb3JzLmxlbmd0aCA+IDAgPyAoZmluZGluZ3MubGVuZ3RoID4gMCA/ICdwYXJ0aWFsJyA6ICdmYWlsZWQnKSA6ICdjb21wbGV0ZWQnLFxuICAgICAgICB0YXJnZXQ6IGNvbnRleHQucHJpbWFyeUhvc3RuYW1lLFxuICAgICAgICBzdGFydGVkQXQsXG4gICAgICAgIGZpbmlzaGVkQXQsXG4gICAgICAgIG91dHB1dENvdW50OiBmaW5kaW5ncy5sZW5ndGgsXG4gICAgICAgIHdhcm5pbmdzOiB3YXJuaW5ncy5tYXAoKHdhcm5pbmcpID0+IHdhcm5pbmcubWVzc2FnZSksXG4gICAgICAgIGVycm9yc1xuICAgICAgfSxcbiAgICAgIGZpbmRpbmdzLFxuICAgICAgd2FybmluZ3MsXG4gICAgICBlcnJvcnM6IGVycm9ycy5tYXAoKG1lc3NhZ2UpID0+ICh7XG4gICAgICAgIGNvZGU6ICdIVFRQX0NPTExFQ1RJT05fRkFJTEVEJyxcbiAgICAgICAgbWVzc2FnZSxcbiAgICAgICAgcmVjb3ZlcmFibGU6IHRydWVcbiAgICAgIH0pKVxuICAgIH07XG4gIH1cbn07XG5cbmFzeW5jIGZ1bmN0aW9uIGZpcnN0U3VjY2Vzc2Z1bEZldGNoKFxuICBiYXNlVXJsczogc3RyaW5nW10sXG4gIHBhdGg6IHN0cmluZyxcbiAgdGltZW91dE1zOiBudW1iZXJcbik6IFByb21pc2U8RmV0Y2hSZXN1bHQgfCB1bmRlZmluZWQ+IHtcbiAgZm9yIChjb25zdCBiYXNlVXJsIG9mIGJhc2VVcmxzKSB7XG4gICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZmV0Y2hUZXh0KGAke2Jhc2VVcmx9JHtwYXRofWAsIHRpbWVvdXRNcyk7XG4gICAgaWYgKHJlc3VsdC5vaykge1xuICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gdW5kZWZpbmVkO1xufVxuXG5hc3luYyBmdW5jdGlvbiBmZXRjaFRleHQodXJsOiBzdHJpbmcsIHRpbWVvdXRNczogbnVtYmVyKTogUHJvbWlzZTxGZXRjaFJlc3VsdD4ge1xuICB0cnkge1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2godXJsLCB7XG4gICAgICBtZXRob2Q6ICdHRVQnLFxuICAgICAgcmVkaXJlY3Q6ICdmb2xsb3cnLFxuICAgICAgc2lnbmFsOiBBYm9ydFNpZ25hbC50aW1lb3V0KHRpbWVvdXRNcyksXG4gICAgICBoZWFkZXJzOiB7XG4gICAgICAgICd1c2VyLWFnZW50JzogJ0JMQU5DSEUtT1NJTlQvMC4xLjAnXG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBjb25zdCBib2R5ID0gYXdhaXQgcmVzcG9uc2UudGV4dCgpO1xuICAgIHJldHVybiB7XG4gICAgICB1cmw6IHJlc3BvbnNlLnVybCxcbiAgICAgIG9rOiByZXNwb25zZS5vayxcbiAgICAgIHN0YXR1czogcmVzcG9uc2Uuc3RhdHVzLFxuICAgICAgaGVhZGVyczogY29sbGVjdEhlYWRlcnMocmVzcG9uc2UuaGVhZGVycyksXG4gICAgICBib2R5OiBib2R5LnNsaWNlKDAsIDEwMF8wMDApXG4gICAgfTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHVybCxcbiAgICAgIG9rOiBmYWxzZSxcbiAgICAgIHN0YXR1czogMCxcbiAgICAgIGhlYWRlcnM6IHt9LFxuICAgICAgYm9keTogJydcbiAgICB9O1xuICB9XG59XG5cbmZ1bmN0aW9uIGJ1aWxkSG9tZXBhZ2VGaW5kaW5nKHJlc3VsdDogRmV0Y2hSZXN1bHQpOiBPc2ludEZpbmRpbmcge1xuICByZXR1cm4ge1xuICAgIGZpbmRpbmdJZDogY3JlYXRlSWQoJ2ZpbmRpbmcnKSxcbiAgICBjYXRlZ29yeTogJ2h0dHAtc3VyZmFjZScsXG4gICAgdGl0bGU6IGBQdWJsaWMgd2ViIHN1cmZhY2UgZm9yICR7cmVzdWx0LnVybH1gLFxuICAgIGRlc2NyaXB0aW9uOiAnVGhlIHRhcmdldCByZXR1cm5lZCBhIHB1YmxpYyB3ZWIgcmVzcG9uc2UgdGhhdCBjYW4gZ3VpZGUgc2NvcGUgZmFtaWxpYXJpemF0aW9uLicsXG4gICAgdGFyZ2V0OiByZXN1bHQudXJsLFxuICAgIGNvbmZpZGVuY2U6ICdoaWdoJyxcbiAgICBzb3VyY2VUb29sczogWydidWlsdGluLWh0dHAnXSxcbiAgICB0YWdzOiBbJ2h0dHAnLCAnaGVhZGVycyddLFxuICAgIGV2aWRlbmNlOiB7XG4gICAgICBzdGF0dXM6IHJlc3VsdC5zdGF0dXMsXG4gICAgICBoZWFkZXJzOiByZXN1bHQuaGVhZGVycyxcbiAgICAgIHRpdGxlOiBleHRyYWN0SHRtbFRpdGxlKHJlc3VsdC5ib2R5KSA/PyBudWxsLFxuICAgICAgbWFuaWZlc3RIcmVmOiBleHRyYWN0TWFuaWZlc3RIcmVmKHJlc3VsdC5ib2R5KSA/PyBudWxsXG4gICAgfVxuICB9O1xufVxuXG5mdW5jdGlvbiBidWlsZFJvYm90c0ZpbmRpbmcoaG9zdG5hbWU6IHN0cmluZywgcmVzdWx0OiBGZXRjaFJlc3VsdCk6IE9zaW50RmluZGluZyB7XG4gIGNvbnN0IHNpdGVtYXBMaW5lcyA9IHJlc3VsdC5ib2R5XG4gICAgLnNwbGl0KC9cXHI/XFxuLylcbiAgICAuZmlsdGVyKChsaW5lKSA9PiAvXnNpdGVtYXA6L2kudGVzdChsaW5lKSlcbiAgICAuc2xpY2UoMCwgMTUpO1xuICBjb25zdCBkaXNhbGxvd0NvdW50ID0gcmVzdWx0LmJvZHlcbiAgICAuc3BsaXQoL1xccj9cXG4vKVxuICAgIC5maWx0ZXIoKGxpbmUpID0+IC9eZGlzYWxsb3c6L2kudGVzdChsaW5lKSkubGVuZ3RoO1xuXG4gIHJldHVybiB7XG4gICAgZmluZGluZ0lkOiBjcmVhdGVJZCgnZmluZGluZycpLFxuICAgIGNhdGVnb3J5OiAnZG9jdW1lbnQtcmVmZXJlbmNlJyxcbiAgICB0aXRsZTogYHJvYm90cy50eHQgb2JzZXJ2YXRpb25zIGZvciAke2hvc3RuYW1lfWAsXG4gICAgZGVzY3JpcHRpb246ICdQdWJsaWMgY3Jhd2xlciBwb2xpY3kgYW5kIHJlZmVyZW5jZWQgc2l0ZW1hcCBoaW50cyB3ZXJlIGNvbGxlY3RlZCBmcm9tIHJvYm90cy50eHQuJyxcbiAgICB0YXJnZXQ6IGhvc3RuYW1lLFxuICAgIGNvbmZpZGVuY2U6ICdoaWdoJyxcbiAgICBzb3VyY2VUb29sczogWydidWlsdGluLWh0dHAnXSxcbiAgICB0YWdzOiBbJ2h0dHAnLCAncm9ib3RzJ10sXG4gICAgZXZpZGVuY2U6IHtcbiAgICAgIHVybDogcmVzdWx0LnVybCxcbiAgICAgIHN0YXR1czogcmVzdWx0LnN0YXR1cyxcbiAgICAgIGRpc2FsbG93Q291bnQsXG4gICAgICBzaXRlbWFwUmVmZXJlbmNlczogc2l0ZW1hcExpbmVzXG4gICAgfVxuICB9O1xufVxuXG5mdW5jdGlvbiBidWlsZFNlY3VyaXR5VHh0RmluZGluZyhob3N0bmFtZTogc3RyaW5nLCByZXN1bHQ6IEZldGNoUmVzdWx0KTogT3NpbnRGaW5kaW5nIHtcbiAgY29uc3QgY29udGFjdHMgPSBleHRyYWN0U2VjdXJpdHlUeHRWYWx1ZXMocmVzdWx0LmJvZHksICdjb250YWN0Jyk7XG4gIGNvbnN0IHBvbGljaWVzID0gZXh0cmFjdFNlY3VyaXR5VHh0VmFsdWVzKHJlc3VsdC5ib2R5LCAncG9saWN5Jyk7XG4gIGNvbnN0IGFja25vd2xlZGdtZW50cyA9IGV4dHJhY3RTZWN1cml0eVR4dFZhbHVlcyhyZXN1bHQuYm9keSwgJ2Fja25vd2xlZGdtZW50cycpO1xuXG4gIHJldHVybiB7XG4gICAgZmluZGluZ0lkOiBjcmVhdGVJZCgnZmluZGluZycpLFxuICAgIGNhdGVnb3J5OiAnc2VjdXJpdHktY29udGFjdCcsXG4gICAgdGl0bGU6IGBzZWN1cml0eS50eHQgY29udGFjdHMgZm9yICR7aG9zdG5hbWV9YCxcbiAgICBkZXNjcmlwdGlvbjogJ1B1YmxpYyBzZWN1cml0eSBjb250YWN0IG1ldGFkYXRhIHdhcyBleHBvc2VkIHRocm91Z2ggYSBzZWN1cml0eS50eHQgZmlsZS4nLFxuICAgIHRhcmdldDogaG9zdG5hbWUsXG4gICAgY29uZmlkZW5jZTogJ2hpZ2gnLFxuICAgIHNvdXJjZVRvb2xzOiBbJ2J1aWx0aW4taHR0cCddLFxuICAgIHRhZ3M6IFsnaHR0cCcsICdzZWN1cml0eS10eHQnXSxcbiAgICBldmlkZW5jZToge1xuICAgICAgdXJsOiByZXN1bHQudXJsLFxuICAgICAgc3RhdHVzOiByZXN1bHQuc3RhdHVzLFxuICAgICAgY29udGFjdHMsXG4gICAgICBwb2xpY2llcyxcbiAgICAgIGFja25vd2xlZGdtZW50c1xuICAgIH1cbiAgfTtcbn1cblxuZnVuY3Rpb24gZXh0cmFjdFNlY3VyaXR5VHh0VmFsdWVzKGJvZHk6IHN0cmluZywga2V5OiBzdHJpbmcpOiBzdHJpbmdbXSB7XG4gIHJldHVybiBib2R5XG4gICAgLnNwbGl0KC9cXHI/XFxuLylcbiAgICAubWFwKChsaW5lKSA9PiBsaW5lLnRyaW0oKSlcbiAgICAuZmlsdGVyKChsaW5lKSA9PiBsaW5lLnRvTG93ZXJDYXNlKCkuc3RhcnRzV2l0aChgJHtrZXkudG9Mb3dlckNhc2UoKX06YCkpXG4gICAgLm1hcCgobGluZSkgPT4gbGluZS5zcGxpdCgnOicpLnNsaWNlKDEpLmpvaW4oJzonKS50cmltKCkpXG4gICAgLmZpbHRlcihCb29sZWFuKTtcbn1cblxuZnVuY3Rpb24gZXh0cmFjdFRlY2hub2xvZ3lFdmlkZW5jZShyZXN1bHQ6IEZldGNoUmVzdWx0KTogUmVjb3JkPHN0cmluZywgc3RyaW5nPiB7XG4gIGNvbnN0IGV2aWRlbmNlOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+ID0ge307XG4gIGNvbnN0IHNlcnZlciA9IHJlc3VsdC5oZWFkZXJzLnNlcnZlcjtcbiAgY29uc3QgcG93ZXJlZEJ5ID0gcmVzdWx0LmhlYWRlcnNbJ3gtcG93ZXJlZC1ieSddO1xuICBjb25zdCBjc3AgPSByZXN1bHQuaGVhZGVyc1snY29udGVudC1zZWN1cml0eS1wb2xpY3knXTtcbiAgY29uc3QgaHN0cyA9IHJlc3VsdC5oZWFkZXJzWydzdHJpY3QtdHJhbnNwb3J0LXNlY3VyaXR5J107XG4gIGNvbnN0IG1hbmlmZXN0SHJlZiA9IGV4dHJhY3RNYW5pZmVzdEhyZWYocmVzdWx0LmJvZHkpO1xuXG4gIGlmIChzZXJ2ZXIpIHtcbiAgICBldmlkZW5jZS5zZXJ2ZXIgPSBzZXJ2ZXI7XG4gIH1cbiAgaWYgKHBvd2VyZWRCeSkge1xuICAgIGV2aWRlbmNlLnhQb3dlcmVkQnkgPSBwb3dlcmVkQnk7XG4gIH1cbiAgaWYgKGNzcCkge1xuICAgIGV2aWRlbmNlLmNvbnRlbnRTZWN1cml0eVBvbGljeSA9IGNzcDtcbiAgfVxuICBpZiAoaHN0cykge1xuICAgIGV2aWRlbmNlLnN0cmljdFRyYW5zcG9ydFNlY3VyaXR5ID0gaHN0cztcbiAgfVxuICBpZiAobWFuaWZlc3RIcmVmKSB7XG4gICAgZXZpZGVuY2UubWFuaWZlc3RIcmVmID0gbWFuaWZlc3RIcmVmO1xuICB9XG5cbiAgcmV0dXJuIGV2aWRlbmNlO1xufVxuXG5mdW5jdGlvbiBleHRyYWN0SHRtbFRpdGxlKGJvZHk6IHN0cmluZyk6IHN0cmluZyB8IHVuZGVmaW5lZCB7XG4gIGNvbnN0IG1hdGNoID0gYm9keS5tYXRjaCgvPHRpdGxlW14+XSo+KFtePF0rKTxcXC90aXRsZT4vaSk7XG4gIHJldHVybiBtYXRjaD8uWzFdPy50cmltKCk7XG59XG5cbmZ1bmN0aW9uIGV4dHJhY3RNYW5pZmVzdEhyZWYoYm9keTogc3RyaW5nKTogc3RyaW5nIHwgdW5kZWZpbmVkIHtcbiAgY29uc3QgbWF0Y2ggPSBib2R5Lm1hdGNoKC88bGlua1tePl0rcmVsPVtcIiddW15cIiddKm1hbmlmZXN0W15cIiddKltcIiddW14+XStocmVmPVtcIiddKFteXCInXSspW1wiJ10vaSk7XG4gIHJldHVybiBtYXRjaD8uWzFdPy50cmltKCk7XG59XG5cbmZ1bmN0aW9uIGNvbGxlY3RIZWFkZXJzKGhlYWRlcnM6IEhlYWRlcnMpOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+IHtcbiAgY29uc3QgdmFsdWVzOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+ID0ge307XG4gIGhlYWRlcnMuZm9yRWFjaCgodmFsdWUsIGtleSkgPT4ge1xuICAgIHZhbHVlc1trZXldID0gdmFsdWU7XG4gIH0pO1xuICByZXR1cm4gdmFsdWVzO1xufVxuXG5mdW5jdGlvbiBjcmVhdGVJZChwcmVmaXg6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiBgJHtwcmVmaXh9XyR7RGF0ZS5ub3coKS50b1N0cmluZygzNil9XyR7Y3J5cHRvLnJhbmRvbVVVSUQoKX1gO1xufVxuIiwgImltcG9ydCB0bHMgZnJvbSAnbm9kZTp0bHMnO1xuaW1wb3J0IHR5cGUgeyBFeHBvcnRXYXJuaW5nLCBPc2ludEZpbmRpbmcgfSBmcm9tICcuLi8uLi8uLi9zaGFyZWQtc2NoZW1hL3NyYyc7XG5pbXBvcnQgdHlwZSB7IENvbGxlY3RvckRlZmluaXRpb24sIENvbGxlY3RvclJ1bk91dHB1dCB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgY29uc3QgdGxzQ29sbGVjdG9yOiBDb2xsZWN0b3JEZWZpbml0aW9uID0ge1xuICBpZDogJ2J1aWx0aW4tdGxzJyxcbiAgbmFtZTogJ0J1aWx0LWluIFRMUyBDb2xsZWN0b3InLFxuICBhc3luYyBydW4oY29udGV4dCk6IFByb21pc2U8Q29sbGVjdG9yUnVuT3V0cHV0PiB7XG4gICAgY29uc3Qgc3RhcnRlZEF0ID0gbmV3IERhdGUoKS50b0lTT1N0cmluZygpO1xuICAgIGNvbnN0IHdhcm5pbmdzOiBFeHBvcnRXYXJuaW5nW10gPSBbXTtcbiAgICBjb25zdCBmaW5kaW5nczogT3NpbnRGaW5kaW5nW10gPSBbXTtcbiAgICBjb25zdCBlcnJvcnM6IHN0cmluZ1tdID0gW107XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgY2VydGlmaWNhdGUgPSBhd2FpdCBjb25uZWN0Rm9yQ2VydGlmaWNhdGUoY29udGV4dC5wcmltYXJ5SG9zdG5hbWUsIGNvbnRleHQudGltZW91dE1zKTtcbiAgICAgIGZpbmRpbmdzLnB1c2goe1xuICAgICAgICBmaW5kaW5nSWQ6IGNyZWF0ZUlkKCdmaW5kaW5nJyksXG4gICAgICAgIGNhdGVnb3J5OiAndGxzLWNlcnRpZmljYXRlJyxcbiAgICAgICAgdGl0bGU6IGBUTFMgY2VydGlmaWNhdGUgbWV0YWRhdGEgZm9yICR7Y29udGV4dC5wcmltYXJ5SG9zdG5hbWV9YCxcbiAgICAgICAgZGVzY3JpcHRpb246ICdUaGUgdGFyZ2V0IGV4cG9zZWQgY2VydGlmaWNhdGUgbWV0YWRhdGEgb24gVENQLzQ0MyB0aGF0IGNhbiByZXZlYWwgcmVsYXRlZCBuYW1lcyBhbmQgaXNzdWFuY2UgZGV0YWlscy4nLFxuICAgICAgICB0YXJnZXQ6IGNvbnRleHQucHJpbWFyeUhvc3RuYW1lLFxuICAgICAgICBjb25maWRlbmNlOiAnaGlnaCcsXG4gICAgICAgIHNvdXJjZVRvb2xzOiBbJ2J1aWx0aW4tdGxzJ10sXG4gICAgICAgIHRhZ3M6IFsndGxzJywgJ2NlcnRpZmljYXRlJ10sXG4gICAgICAgIGV2aWRlbmNlOiBjZXJ0aWZpY2F0ZVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSBlcnJvciBpbnN0YW5jZW9mIEVycm9yID8gZXJyb3IubWVzc2FnZSA6IFN0cmluZyhlcnJvcik7XG4gICAgICB3YXJuaW5ncy5wdXNoKHtcbiAgICAgICAgY29kZTogJ1RMU19NRVRBREFUQV9VTkFWQUlMQUJMRScsXG4gICAgICAgIG1lc3NhZ2U6IGBUTFMgY2VydGlmaWNhdGUgbWV0YWRhdGEgd2FzIHVuYXZhaWxhYmxlIGZvciAke2NvbnRleHQucHJpbWFyeUhvc3RuYW1lfTogJHttZXNzYWdlfWAsXG4gICAgICAgIHNldmVyaXR5OiAnaW5mbydcbiAgICAgIH0pO1xuICAgICAgZXJyb3JzLnB1c2gobWVzc2FnZSk7XG4gICAgfVxuXG4gICAgY29uc3QgZmluaXNoZWRBdCA9IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKTtcbiAgICByZXR1cm4ge1xuICAgICAgdG9vbEV4ZWN1dGlvbjoge1xuICAgICAgICB0b29sSWQ6ICdidWlsdGluLXRscycsXG4gICAgICAgIG5hbWU6ICdCdWlsdC1pbiBUTFMgQ29sbGVjdG9yJyxcbiAgICAgICAgbW9kZTogJ2J1aWx0aW4nLFxuICAgICAgICBzdGF0dXM6IGZpbmRpbmdzLmxlbmd0aCA+IDAgPyAnY29tcGxldGVkJyA6ICdwYXJ0aWFsJyxcbiAgICAgICAgdGFyZ2V0OiBjb250ZXh0LnByaW1hcnlIb3N0bmFtZSxcbiAgICAgICAgc3RhcnRlZEF0LFxuICAgICAgICBmaW5pc2hlZEF0LFxuICAgICAgICBvdXRwdXRDb3VudDogZmluZGluZ3MubGVuZ3RoLFxuICAgICAgICB3YXJuaW5nczogd2FybmluZ3MubWFwKCh3YXJuaW5nKSA9PiB3YXJuaW5nLm1lc3NhZ2UpLFxuICAgICAgICBlcnJvcnNcbiAgICAgIH0sXG4gICAgICBmaW5kaW5ncyxcbiAgICAgIHdhcm5pbmdzLFxuICAgICAgZXJyb3JzOiBmaW5kaW5ncy5sZW5ndGggPiAwXG4gICAgICAgID8gW11cbiAgICAgICAgOiBlcnJvcnMubWFwKChtZXNzYWdlKSA9PiAoe1xuICAgICAgICAgICAgY29kZTogJ1RMU19DT0xMRUNUSU9OX0ZBSUxFRCcsXG4gICAgICAgICAgICBtZXNzYWdlLFxuICAgICAgICAgICAgcmVjb3ZlcmFibGU6IHRydWVcbiAgICAgICAgICB9KSlcbiAgICB9O1xuICB9XG59O1xuXG5mdW5jdGlvbiBjb25uZWN0Rm9yQ2VydGlmaWNhdGUoXG4gIGhvc3RuYW1lOiBzdHJpbmcsXG4gIHRpbWVvdXRNczogbnVtYmVyXG4pOiBQcm9taXNlPFJlY29yZDxzdHJpbmcsIHN0cmluZyB8IG51bGw+PiB7XG4gIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgY29uc3Qgc29ja2V0ID0gdGxzLmNvbm5lY3Qoe1xuICAgICAgaG9zdDogaG9zdG5hbWUsXG4gICAgICBwb3J0OiA0NDMsXG4gICAgICBzZXJ2ZXJuYW1lOiBob3N0bmFtZSxcbiAgICAgIHJlamVjdFVuYXV0aG9yaXplZDogZmFsc2VcbiAgICB9KTtcblxuICAgIGNvbnN0IGZhaWwgPSAobWVzc2FnZTogc3RyaW5nKSA9PiB7XG4gICAgICBzb2NrZXQuZGVzdHJveSgpO1xuICAgICAgcmVqZWN0KG5ldyBFcnJvcihtZXNzYWdlKSk7XG4gICAgfTtcblxuICAgIHNvY2tldC5zZXRUaW1lb3V0KHRpbWVvdXRNcywgKCkgPT4gZmFpbChgdGltZWQgb3V0IGFmdGVyICR7dGltZW91dE1zfW1zYCkpO1xuICAgIHNvY2tldC5vbignZXJyb3InLCAoZXJyb3IpID0+IGZhaWwoZXJyb3IubWVzc2FnZSkpO1xuICAgIHNvY2tldC5vbignc2VjdXJlQ29ubmVjdCcsICgpID0+IHtcbiAgICAgIGNvbnN0IGNlcnRpZmljYXRlID0gc29ja2V0LmdldFBlZXJDZXJ0aWZpY2F0ZSh0cnVlKTtcbiAgICAgIHNvY2tldC5lbmQoKTtcbiAgICAgIGlmICghY2VydGlmaWNhdGUgfHwgT2JqZWN0LmtleXMoY2VydGlmaWNhdGUpLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdubyBwZWVyIGNlcnRpZmljYXRlIHdhcyBwcmVzZW50ZWQnKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgcmVzb2x2ZSh7XG4gICAgICAgIHN1YmplY3Q6IHN0cmluZ2lmeUNlcnRpZmljYXRlRmllbGQoY2VydGlmaWNhdGUuc3ViamVjdCksXG4gICAgICAgIGlzc3Vlcjogc3RyaW5naWZ5Q2VydGlmaWNhdGVGaWVsZChjZXJ0aWZpY2F0ZS5pc3N1ZXIpLFxuICAgICAgICB2YWxpZEZyb206IGNlcnRpZmljYXRlLnZhbGlkX2Zyb20gPz8gbnVsbCxcbiAgICAgICAgdmFsaWRUbzogY2VydGlmaWNhdGUudmFsaWRfdG8gPz8gbnVsbCxcbiAgICAgICAgc2VyaWFsTnVtYmVyOiBjZXJ0aWZpY2F0ZS5zZXJpYWxOdW1iZXIgPz8gbnVsbCxcbiAgICAgICAgZmluZ2VycHJpbnQyNTY6IGNlcnRpZmljYXRlLmZpbmdlcnByaW50MjU2ID8/IG51bGwsXG4gICAgICAgIHN1YmplY3RBbHROYW1lOiBjZXJ0aWZpY2F0ZS5zdWJqZWN0YWx0bmFtZSA/PyBudWxsXG4gICAgICB9KTtcbiAgICB9KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIHN0cmluZ2lmeUNlcnRpZmljYXRlRmllbGQodmFsdWU6IHVua25vd24pOiBzdHJpbmcgfCBudWxsIHtcbiAgaWYgKHZhbHVlID09IG51bGwpIHtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIGlmICh0eXBlb2YgdmFsdWUgPT09ICdzdHJpbmcnKSB7XG4gICAgcmV0dXJuIHZhbHVlO1xuICB9XG5cbiAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHZhbHVlKTtcbn1cblxuZnVuY3Rpb24gY3JlYXRlSWQocHJlZml4OiBzdHJpbmcpOiBzdHJpbmcge1xuICByZXR1cm4gYCR7cHJlZml4fV8ke0RhdGUubm93KCkudG9TdHJpbmcoMzYpfV8ke2NyeXB0by5yYW5kb21VVUlEKCl9YDtcbn1cbiIsICJpbXBvcnQgdHlwZSB7IE9zaW50RmluZGluZywgT3NpbnROYXJyYXRpdmUsIE9zaW50VG9vbEV4ZWN1dGlvbiB9IGZyb20gJy4uLy4uLy4uL3NoYXJlZC1zY2hlbWEvc3JjJztcblxuZXhwb3J0IGZ1bmN0aW9uIGJ1aWxkSGV1cmlzdGljTmFycmF0aXZlKGlucHV0OiB7XG4gIHByaW1hcnlIb3N0bmFtZTogc3RyaW5nO1xuICBmaW5kaW5nczogT3NpbnRGaW5kaW5nW107XG4gIHRvb2xFeGVjdXRpb25zOiBPc2ludFRvb2xFeGVjdXRpb25bXTtcbn0pOiBPc2ludE5hcnJhdGl2ZSB7XG4gIGNvbnN0IGNhdGVnb3J5Q291bnRzID0gY291bnRCeShpbnB1dC5maW5kaW5ncy5tYXAoKGZpbmRpbmcpID0+IGZpbmRpbmcuY2F0ZWdvcnkpKTtcbiAgY29uc3QgY29tcGxldGVkVG9vbHMgPSBpbnB1dC50b29sRXhlY3V0aW9ucy5maWx0ZXIoKHRvb2wpID0+IHRvb2wuc3RhdHVzID09PSAnY29tcGxldGVkJykubGVuZ3RoO1xuICBjb25zdCBza2lwcGVkVG9vbHMgPSBpbnB1dC50b29sRXhlY3V0aW9ucy5maWx0ZXIoKHRvb2wpID0+IHRvb2wuc3RhdHVzID09PSAnc2tpcHBlZCcpLmxlbmd0aDtcblxuICBjb25zdCB0b3BDYXRlZ29yaWVzID0gT2JqZWN0LmVudHJpZXMoY2F0ZWdvcnlDb3VudHMpXG4gICAgLnNvcnQoKGxlZnQsIHJpZ2h0KSA9PiByaWdodFsxXSAtIGxlZnRbMV0pXG4gICAgLnNsaWNlKDAsIDMpXG4gICAgLm1hcCgoW2NhdGVnb3J5LCBjb3VudF0pID0+IGAke2NhdGVnb3J5fSAoJHtjb3VudH0pYCk7XG5cbiAgY29uc3QgZm9sbG93T25Gb2N1cyA9IG5ldyBTZXQ8c3RyaW5nPigpO1xuICBpZiAoKGNhdGVnb3J5Q291bnRzLmhvc3RuYW1lID8/IDApID4gMCkge1xuICAgIGZvbGxvd09uRm9jdXMuYWRkKCdSZXZpZXcgcmVsYXRlZCBwdWJsaWMgaG9zdG5hbWVzIGFuZCB0aGlyZC1wYXJ0eSBlbmRwb2ludHMgYmVmb3JlIGRlZXBlciB0ZXN0aW5nIGJlZ2lucy4nKTtcbiAgfVxuICBpZiAoKGNhdGVnb3J5Q291bnRzWydhcmNoaXZlLXJlZmVyZW5jZSddID8/IDApID4gMCkge1xuICAgIGZvbGxvd09uRm9jdXMuYWRkKCdDb21wYXJlIGFyY2hpdmVkIFVSTCByZWZlcmVuY2VzIGFnYWluc3QgdGhlIGN1cnJlbnQgYXBwbGljYXRpb24gbWFwIHRvIHNwb3QgbGVnYWN5IGF0dGFjayBzdXJmYWNlLicpO1xuICB9XG4gIGlmICgoY2F0ZWdvcnlDb3VudHNbJ3NlY3VyaXR5LWNvbnRhY3QnXSA/PyAwKSA9PT0gMCkge1xuICAgIGZvbGxvd09uRm9jdXMuYWRkKCdObyBwdWJsaWMgc2VjdXJpdHkudHh0IGNvbnRhY3Qgd2FzIG9ic2VydmVkOyBwbGFuIGNvb3JkaW5hdGlvbiBjaGFubmVscyBzZXBhcmF0ZWx5LicpO1xuICB9XG4gIGlmICgoY2F0ZWdvcnlDb3VudHNbJ3RlY2hub2xvZ3ktaGludCddID8/IDApID4gMCkge1xuICAgIGZvbGxvd09uRm9jdXMuYWRkKCdVc2UgcHVibGljIHRlY2hub2xvZ3kgaGludHMgdG8gcHJpb3JpdGl6ZSBtYW51YWwgcmV2aWV3IHBhdGhzLCBub3QgdG8gaW5mZXIgdnVsbmVyYWJpbGl0aWVzLicpO1xuICB9XG4gIGlmIChmb2xsb3dPbkZvY3VzLnNpemUgPT09IDApIHtcbiAgICBmb2xsb3dPbkZvY3VzLmFkZCgnVXNlIHRoZSBpbmZvcm1hdGlvbmFsIE9TSU5UIGZpbmRpbmdzIHRvIGd1aWRlIHNjb3BlIGZhbWlsaWFyaXphdGlvbiBhbmQgcmVxdWVzdCBwcmlvcml0aXphdGlvbi4nKTtcbiAgfVxuXG4gIHJldHVybiB7XG4gICAgaGVhZGxpbmU6IGBQdWJsaWMgT1NJTlQgc3VtbWFyeSBmb3IgJHtpbnB1dC5wcmltYXJ5SG9zdG5hbWV9YCxcbiAgICBzdW1tYXJ5OlxuICAgICAgaW5wdXQuZmluZGluZ3MubGVuZ3RoID09PSAwXG4gICAgICAgID8gYE5vIG5vcm1hbGl6ZWQgT1NJTlQgZmluZGluZ3Mgd2VyZSBwcm9kdWNlZCBmb3IgJHtpbnB1dC5wcmltYXJ5SG9zdG5hbWV9LiBDb21wbGV0ZWQgdG9vbHM6ICR7Y29tcGxldGVkVG9vbHN9OyBza2lwcGVkIHRvb2xzOiAke3NraXBwZWRUb29sc30uYFxuICAgICAgICA6IGBDb2xsZWN0ZWQgJHtpbnB1dC5maW5kaW5ncy5sZW5ndGh9IGluZm9ybWF0aW9uYWwgZmluZGluZ3MgZm9yICR7aW5wdXQucHJpbWFyeUhvc3RuYW1lfS4gVGhlIHN0cm9uZ2VzdCBjdXJyZW50IHRoZW1lcyBhcmUgJHt0b3BDYXRlZ29yaWVzLmpvaW4oJywgJyl9LiBDb21wbGV0ZWQgdG9vbHM6ICR7Y29tcGxldGVkVG9vbHN9OyBza2lwcGVkIHRvb2xzOiAke3NraXBwZWRUb29sc30uYCxcbiAgICBmb2xsb3dPbkZvY3VzOiBbLi4uZm9sbG93T25Gb2N1c10sXG4gICAgcmVwb3J0UmVhZHlOb3RlczogW1xuICAgICAgJ1RoaXMgb3V0cHV0IGlzIGluZm9ybWF0aW9uYWwgT1NJTlQgb25seSBhbmQgZG9lcyBub3QgdmFsaWRhdGUgdnVsbmVyYWJpbGl0aWVzIG9yIGJ1c2luZXNzIGltcGFjdC4nLFxuICAgICAgJ1NraXBwZWQgdG9vbHMgdXN1YWxseSBpbmRpY2F0ZSBsb2NhbCBlbnZpcm9ubWVudCBnYXBzIHJhdGhlciB0aGFuIGFic2VuY2Ugb2YgcHVibGljIGRhdGEuJyxcbiAgICAgICdDb3VudHMgYW5kIHN1bW1hcmllcyBzaG91bGQgYmUgdXNlZCB0byBwcmlvcml0aXplIG1hbnVhbCB0ZXN0aW5nLCBub3QgcmVwbGFjZSBpdC4nXG4gICAgXVxuICB9O1xufVxuXG5mdW5jdGlvbiBjb3VudEJ5KHZhbHVlczogc3RyaW5nW10pOiBSZWNvcmQ8c3RyaW5nLCBudW1iZXI+IHtcbiAgcmV0dXJuIHZhbHVlcy5yZWR1Y2U8UmVjb3JkPHN0cmluZywgbnVtYmVyPj4oKGFjY3VtdWxhdG9yLCB2YWx1ZSkgPT4ge1xuICAgIGFjY3VtdWxhdG9yW3ZhbHVlXSA9IChhY2N1bXVsYXRvclt2YWx1ZV0gPz8gMCkgKyAxO1xuICAgIHJldHVybiBhY2N1bXVsYXRvcjtcbiAgfSwge30pO1xufVxuIiwgImltcG9ydCB7XG4gIEJMQU5DSEVfT1NJTlRfUkVQT1JUX0tJTkQsXG4gIEJMQU5DSEVfT1NJTlRfU0NIRU1BX1ZFUlNJT04sXG4gIHR5cGUgQmxhbmNoZU9zaW50UmVwb3J0VjEsXG4gIHR5cGUgQmxhbmNoZU9zaW50U2VlZFYxLFxuICB0eXBlIEV4cG9ydFdhcm5pbmdcbn0gZnJvbSAnLi4vLi4vc2hhcmVkLXNjaGVtYS9zcmMnO1xuaW1wb3J0IHsgYnVpbGRIZXVyaXN0aWNOYXJyYXRpdmUgfSBmcm9tICcuL2FuYWx5c2lzL2hldXJpc3RpY05hcnJhdGl2ZSc7XG5pbXBvcnQgdHlwZSB7IENvbGxlY3RvclJ1bk91dHB1dCB9IGZyb20gJy4vY29sbGVjdG9ycy90eXBlcyc7XG5pbXBvcnQgeyBleHRyYWN0UmVsYXRlZEhvc3RuYW1lcyB9IGZyb20gJy4vc2hhcmVkL3RhcmdldGluZyc7XG5cbmV4cG9ydCBmdW5jdGlvbiBidWlsZE9zaW50UmVwb3J0KGlucHV0OiB7XG4gIHNlZWQ6IEJsYW5jaGVPc2ludFNlZWRWMTtcbiAgb3V0cHV0czogQ29sbGVjdG9yUnVuT3V0cHV0W107XG59KTogQmxhbmNoZU9zaW50UmVwb3J0VjEge1xuICBjb25zdCBmaW5kaW5ncyA9IGlucHV0Lm91dHB1dHMuZmxhdE1hcCgob3V0cHV0KSA9PiBvdXRwdXQuZmluZGluZ3MpO1xuICBjb25zdCB0b29sRXhlY3V0aW9ucyA9IGlucHV0Lm91dHB1dHMubWFwKChvdXRwdXQpID0+IG91dHB1dC50b29sRXhlY3V0aW9uKTtcbiAgY29uc3Qgd2FybmluZ3MgPSBkZWR1cGVXYXJuaW5ncyhbXG4gICAgLi4uaW5wdXQuc2VlZC53YXJuaW5ncyxcbiAgICAuLi5pbnB1dC5vdXRwdXRzLmZsYXRNYXAoKG91dHB1dCkgPT4gb3V0cHV0Lndhcm5pbmdzKVxuICBdKTtcbiAgY29uc3QgZXJyb3JzID0gaW5wdXQub3V0cHV0cy5mbGF0TWFwKChvdXRwdXQpID0+IG91dHB1dC5lcnJvcnMpO1xuICBjb25zdCByZWxhdGVkSG9zdG5hbWVzID0gZXh0cmFjdFJlbGF0ZWRIb3N0bmFtZXMoaW5wdXQuc2VlZCk7XG5cbiAgY29uc3QgbmFycmF0aXZlID0gYnVpbGRIZXVyaXN0aWNOYXJyYXRpdmUoe1xuICAgIHByaW1hcnlIb3N0bmFtZTogaW5wdXQuc2VlZC5zZWVkLnByaW1hcnlIb3N0bmFtZSxcbiAgICBmaW5kaW5ncyxcbiAgICB0b29sRXhlY3V0aW9uc1xuICB9KTtcbiAgY29uc3QgZmluZGluZ3NCeUNhdGVnb3J5ID0gY291bnRCeShmaW5kaW5ncy5tYXAoKGZpbmRpbmcpID0+IGZpbmRpbmcuY2F0ZWdvcnkpKTtcblxuICByZXR1cm4ge1xuICAgIGtpbmQ6IEJMQU5DSEVfT1NJTlRfUkVQT1JUX0tJTkQsXG4gICAgc2NoZW1hVmVyc2lvbjogQkxBTkNIRV9PU0lOVF9TQ0hFTUFfVkVSU0lPTixcbiAgICByZXBvcnRNZXRhZGF0YToge1xuICAgICAgcmVwb3J0SWQ6IGNyZWF0ZUlkKCdvc2ludCcpLFxuICAgICAgZ2VuZXJhdGVkQXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcbiAgICAgIGdlbmVyYXRlZEJ5OiB7XG4gICAgICAgIHByb2R1Y3Q6ICdCTEFOQ0hFJyxcbiAgICAgICAgY29tcG9uZW50OiAnb3NpbnQtb3JjaGVzdHJhdG9yL2NsaScsXG4gICAgICAgIHZlcnNpb246ICcwLjEuMCdcbiAgICAgIH0sXG4gICAgICBzZWVkSWQ6IGlucHV0LnNlZWQuc2VlZE1ldGFkYXRhLnNlZWRJZFxuICAgIH0sXG4gICAgc2NvcGU6IGlucHV0LnNlZWQuc2NvcGUsXG4gICAgdGFyZ2V0OiB7XG4gICAgICBwcmltYXJ5SG9zdG5hbWU6IGlucHV0LnNlZWQuc2VlZC5wcmltYXJ5SG9zdG5hbWUsXG4gICAgICBhcHBhcmVudFJvb3REb21haW46IGlucHV0LnNlZWQuc2VlZC5hcHBhcmVudFJvb3REb21haW4sXG4gICAgICB0YXJnZXRVcmw6IGlucHV0LnNlZWQuc2VlZC50YXJnZXRVcmwsXG4gICAgICB0YXJnZXRPcmlnaW46IGlucHV0LnNlZWQuc2VlZC50YXJnZXRPcmlnaW4sXG4gICAgICByZWxhdGVkSG9zdG5hbWVzXG4gICAgfSxcbiAgICBzZWVkOiBpbnB1dC5zZWVkLFxuICAgIHRvb2xFeGVjdXRpb25zLFxuICAgIGZpbmRpbmdzLFxuICAgIHdhcm5pbmdzLFxuICAgIGVycm9ycyxcbiAgICBuYXJyYXRpdmUsXG4gICAgc3VtbWFyeToge1xuICAgICAgZmluZGluZ0NvdW50OiBmaW5kaW5ncy5sZW5ndGgsXG4gICAgICBmaW5kaW5nc0J5Q2F0ZWdvcnksXG4gICAgICBjb21wbGV0ZWRUb29sczogdG9vbEV4ZWN1dGlvbnMuZmlsdGVyKCh0b29sKSA9PiB0b29sLnN0YXR1cyA9PT0gJ2NvbXBsZXRlZCcpLmxlbmd0aCxcbiAgICAgIHNraXBwZWRUb29sczogdG9vbEV4ZWN1dGlvbnMuZmlsdGVyKCh0b29sKSA9PiB0b29sLnN0YXR1cyA9PT0gJ3NraXBwZWQnKS5sZW5ndGgsXG4gICAgICBmYWlsZWRUb29sczogdG9vbEV4ZWN1dGlvbnMuZmlsdGVyKCh0b29sKSA9PiB0b29sLnN0YXR1cyA9PT0gJ2ZhaWxlZCcpLmxlbmd0aFxuICAgIH1cbiAgfTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHJlbmRlclJlcG9ydE1hcmtkb3duKHJlcG9ydDogQmxhbmNoZU9zaW50UmVwb3J0VjEpOiBzdHJpbmcge1xuICBjb25zdCBmaW5kaW5nc1NlY3Rpb24gPVxuICAgIHJlcG9ydC5maW5kaW5ncy5sZW5ndGggPT09IDBcbiAgICAgID8gJy0gTm8gbm9ybWFsaXplZCBpbmZvcm1hdGlvbmFsIE9TSU5UIGZpbmRpbmdzIHdlcmUgcHJvZHVjZWQuXFxuJ1xuICAgICAgOiByZXBvcnQuZmluZGluZ3NcbiAgICAgICAgICAubWFwKFxuICAgICAgICAgICAgKGZpbmRpbmcpID0+XG4gICAgICAgICAgICAgIGAtIFske2ZpbmRpbmcuY2F0ZWdvcnl9XSAke2ZpbmRpbmcudGl0bGV9OiAke2ZpbmRpbmcuZGVzY3JpcHRpb259ICh0YXJnZXQ6ICR7ZmluZGluZy50YXJnZXR9KWBcbiAgICAgICAgICApXG4gICAgICAgICAgLmpvaW4oJ1xcbicpO1xuXG4gIGNvbnN0IHRvb2xTZWN0aW9uID0gcmVwb3J0LnRvb2xFeGVjdXRpb25zXG4gICAgLm1hcChcbiAgICAgICh0b29sKSA9PlxuICAgICAgICBgLSAke3Rvb2wubmFtZX0gWyR7dG9vbC5zdGF0dXN9XSB0YXJnZXQ9JHt0b29sLnRhcmdldH0gb3V0cHV0cz0ke3Rvb2wub3V0cHV0Q291bnR9JHtcbiAgICAgICAgICB0b29sLmNvbW1hbmQgPyBgIGNvbW1hbmQ9XFxgJHt0b29sLmNvbW1hbmR9XFxgYCA6ICcnXG4gICAgICAgIH1gXG4gICAgKVxuICAgIC5qb2luKCdcXG4nKTtcblxuICByZXR1cm4gYCMgQkxBTkNIRSBPU0lOVCBTdW1tYXJ5XG5cbkdlbmVyYXRlZDogJHtyZXBvcnQucmVwb3J0TWV0YWRhdGEuZ2VuZXJhdGVkQXR9XG5QcmltYXJ5IEhvc3RuYW1lOiAke3JlcG9ydC50YXJnZXQucHJpbWFyeUhvc3RuYW1lfVxuVGFyZ2V0IFVSTDogJHtyZXBvcnQudGFyZ2V0LnRhcmdldFVybCA/PyAnKG5vdCBwcm92aWRlZCknfVxuXG4jIyBOYXJyYXRpdmVcblxuJHtyZXBvcnQubmFycmF0aXZlLmhlYWRsaW5lfVxuXG4ke3JlcG9ydC5uYXJyYXRpdmUuc3VtbWFyeX1cblxuIyMgRm9sbG93LU9uIEZvY3VzXG5cbiR7cmVwb3J0Lm5hcnJhdGl2ZS5mb2xsb3dPbkZvY3VzLm1hcCgobGluZSkgPT4gYC0gJHtsaW5lfWApLmpvaW4oJ1xcbicpfVxuXG4jIyBSZXBvcnQtUmVhZHkgTm90ZXNcblxuJHtyZXBvcnQubmFycmF0aXZlLnJlcG9ydFJlYWR5Tm90ZXMubWFwKChsaW5lKSA9PiBgLSAke2xpbmV9YCkuam9pbignXFxuJyl9XG5cbiMjIFRvb2wgRXhlY3V0aW9uc1xuXG4ke3Rvb2xTZWN0aW9ufVxuXG4jIyBGaW5kaW5nc1xuXG4ke2ZpbmRpbmdzU2VjdGlvbn1cbmA7XG59XG5cbmZ1bmN0aW9uIGRlZHVwZVdhcm5pbmdzKHdhcm5pbmdzOiBFeHBvcnRXYXJuaW5nW10pOiBFeHBvcnRXYXJuaW5nW10ge1xuICBjb25zdCBzZWVuID0gbmV3IFNldDxzdHJpbmc+KCk7XG4gIGNvbnN0IG91dHB1dDogRXhwb3J0V2FybmluZ1tdID0gW107XG4gIGZvciAoY29uc3Qgd2FybmluZyBvZiB3YXJuaW5ncykge1xuICAgIGNvbnN0IGtleSA9IEpTT04uc3RyaW5naWZ5KHdhcm5pbmcpO1xuICAgIGlmICghc2Vlbi5oYXMoa2V5KSkge1xuICAgICAgc2Vlbi5hZGQoa2V5KTtcbiAgICAgIG91dHB1dC5wdXNoKHdhcm5pbmcpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gb3V0cHV0O1xufVxuXG5mdW5jdGlvbiBjb3VudEJ5KHZhbHVlczogc3RyaW5nW10pOiBSZWNvcmQ8c3RyaW5nLCBudW1iZXI+IHtcbiAgcmV0dXJuIHZhbHVlcy5yZWR1Y2U8UmVjb3JkPHN0cmluZywgbnVtYmVyPj4oKGFjY3VtdWxhdG9yLCB2YWx1ZSkgPT4ge1xuICAgIGFjY3VtdWxhdG9yW3ZhbHVlXSA9IChhY2N1bXVsYXRvclt2YWx1ZV0gPz8gMCkgKyAxO1xuICAgIHJldHVybiBhY2N1bXVsYXRvcjtcbiAgfSwge30pO1xufVxuXG5mdW5jdGlvbiBjcmVhdGVJZChwcmVmaXg6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiBgJHtwcmVmaXh9XyR7RGF0ZS5ub3coKS50b1N0cmluZygzNil9XyR7Y3J5cHRvLnJhbmRvbVVVSUQoKX1gO1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjtBQUFBLE9BQU8sUUFBUTtBQUNmLE9BQU8sVUFBVTtBQUNqQixPQUFPLGFBQWE7OztBQ0ZwQixPQUFPLFNBQVM7QUFVVCxJQUFNLGVBQW9DO0FBQUEsRUFDL0MsSUFBSTtBQUFBLEVBQ0osTUFBTTtBQUFBLEVBQ04sTUFBTSxJQUFJLFNBQXNDO0FBQzlDLFVBQU0sYUFBWSxvQkFBSSxLQUFLLEdBQUUsWUFBWTtBQUN6QyxVQUFNLGNBQWMsUUFBUSxzQkFBc0IsUUFBUTtBQUMxRCxVQUFNLFdBQTRCLENBQUM7QUFDbkMsVUFBTSxXQUEyQixDQUFDO0FBQ2xDLFVBQU0sU0FBbUIsQ0FBQztBQUUxQixVQUFNLFFBQXFCO0FBQUEsTUFDekI7QUFBQSxRQUNFLE9BQU87QUFBQSxRQUNQLFFBQVEsUUFBUTtBQUFBLFFBQ2hCLFNBQVMsWUFBWSxJQUFJLFNBQVMsUUFBUSxlQUFlO0FBQUEsTUFDM0Q7QUFBQSxNQUNBO0FBQUEsUUFDRSxPQUFPO0FBQUEsUUFDUCxRQUFRLFFBQVE7QUFBQSxRQUNoQixTQUFTLFlBQVksSUFBSSxTQUFTLFFBQVEsZUFBZTtBQUFBLE1BQzNEO0FBQUEsTUFDQTtBQUFBLFFBQ0UsT0FBTztBQUFBLFFBQ1AsUUFBUSxRQUFRO0FBQUEsUUFDaEIsU0FBUyxZQUFZLElBQUksYUFBYSxRQUFRLGVBQWU7QUFBQSxNQUMvRDtBQUFBLE1BQ0E7QUFBQSxRQUNFLE9BQU87QUFBQSxRQUNQLFFBQVE7QUFBQSxRQUNSLFNBQVMsWUFBWSxJQUFJLFVBQVUsV0FBVztBQUFBLE1BQ2hEO0FBQUEsTUFDQTtBQUFBLFFBQ0UsT0FBTztBQUFBLFFBQ1AsUUFBUTtBQUFBLFFBQ1IsU0FBUyxZQUFZLElBQUksVUFBVSxXQUFXO0FBQUEsTUFDaEQ7QUFBQSxNQUNBO0FBQUEsUUFDRSxPQUFPO0FBQUEsUUFDUCxRQUFRO0FBQUEsUUFDUixTQUFTLFlB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VTtBQUFBLE1BQ2hCLEtBQUs7QUFDSCxRQUFBQSxTQUFRLFdBQVcsS0FBSyxRQUFRLENBQUM7QUFDakMsaUJBQVM7QUFDVDtBQUFBLE1BQ0YsS0FBSztBQUNILFFBQUFBLFNBQVEsU0FBUyxLQUFLLFFBQVEsQ0FBQztBQUMvQixpQkFBUztBQUNUO0FBQUEsTUFDRixLQUFLO0FBQ0gsUUFBQUEsU0FBUSxZQUFZLEtBQUssUUFBUSxDQUFDO0FBQ2xDLGlCQUFTO0FBQ1Q7QUFBQSxNQUNGLEtBQUs7QUFDSCxRQUFBQSxTQUFRLFlBQVksT0FBTyxLQUFLLFFBQVEsQ0FBQyxLQUFLQSxTQUFRLFNBQVM7QUFDL0QsaUJBQVM7QUFDVDtBQUFBLE1BQ0YsS0FBSztBQUNILFFBQUFBLFNBQVEsdUJBQXVCO0FBQy9CO0FBQUEsTUFDRixLQUFLO0FBQ0gsbUJBQVc7QUFDWCxnQkFBUSxLQUFLLENBQUM7QUFBQSxNQUNoQjtBQUNFLGNBQU0sSUFBSSxNQUFNLHFCQUFxQixRQUFRLEVBQUU7QUFBQSxJQUNuRDtBQUFBLEVBQ0Y7QUFFQSxTQUFPQTtBQUNUO0FBRUEsU0FBUyxhQUFtQjtBQUMxQixVQUFRLE9BQU8sTUFBTTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEsQ0FLdEI7QUFDRDsiLAogICJuYW1lcyI6IFsiY3JlYXRlSWQiLCAiY3JlYXRlSWQiLCAiY3JlYXRlSWQiLCAiY3JlYXRlSWQiLCAicGF0aCIsICJjcmVhdGVJZCIsICJjb3VudEJ5IiwgImNyZWF0ZUlkIiwgIm9wdGlvbnMiXQp9Cg==
