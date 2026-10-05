import tls from 'node:tls';
import type { ExportWarning, OsintFinding } from '../../../shared-schema/src';
import type { CollectorDefinition, CollectorRunOutput } from './types';

export const tlsCollector: CollectorDefinition = {
  id: 'builtin-tls',
  name: 'Built-in TLS Collector',
  async run(context): Promise<CollectorRunOutput> {
    const startedAt = new Date().toISOString();
    const warnings: ExportWarning[] = [];
    const findings: OsintFinding[] = [];
    const errors: string[] = [];

    try {
      const certificate = await connectForCertificate(context.primaryHostname, context.timeoutMs);
      findings.push({
        findingId: createId('finding'),
        category: 'tls-certificate',
        title: `TLS certificate metadata for ${context.primaryHostname}`,
        description: 'The target exposed certificate metadata on TCP/443 that can reveal related names and issuance details.',
        target: context.primaryHostname,
        confidence: 'high',
        sourceTools: ['builtin-tls'],
        tags: ['tls', 'certificate'],
        evidence: certificate
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push({
        code: 'TLS_METADATA_UNAVAILABLE',
        message: `TLS certificate metadata was unavailable for ${context.primaryHostname}: ${message}`,
        severity: 'info'
      });
      errors.push(message);
    }

    const finishedAt = new Date().toISOString();
    return {
      toolExecution: {
        toolId: 'builtin-tls',
        name: 'Built-in TLS Collector',
        mode: 'builtin',
        status: findings.length > 0 ? 'completed' : 'partial',
        target: context.primaryHostname,
        startedAt,
        finishedAt,
        outputCount: findings.length,
        warnings: warnings.map((warning) => warning.message),
        errors
      },
      findings,
      warnings,
      errors: findings.length > 0
        ? []
        : errors.map((message) => ({
            code: 'TLS_COLLECTION_FAILED',
            message,
            recoverable: true
          }))
    };
  }
};

function connectForCertificate(
  hostname: string,
  timeoutMs: number
): Promise<Record<string, string | null>> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false
    });

    const fail = (message: string) => {
      socket.destroy();
      reject(new Error(message));
    };

    socket.setTimeout(timeoutMs, () => fail(`timed out after ${timeoutMs}ms`));
    socket.on('error', (error) => fail(error.message));
    socket.on('secureConnect', () => {
      const certificate = socket.getPeerCertificate(true);
      socket.end();
      if (!certificate || Object.keys(certificate).length === 0) {
        reject(new Error('no peer certificate was presented'));
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

function stringifyCertificateField(value: unknown): string | null {
  if (value == null) {
    return null;
  }

  if (typeof value === 'string') {
    return value;
  }

  return JSON.stringify(value);
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
