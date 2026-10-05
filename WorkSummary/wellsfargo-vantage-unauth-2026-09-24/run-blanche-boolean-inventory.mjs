import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const artifactDirectory = dirname(fileURLToPath(import.meta.url));
const baselinePath = join(artifactDirectory, 'blanche-feature-map-audit.json');
const jsonOutputPath = join(artifactDirectory, 'blanche-boolean-inventory.json');
const markdownOutputPath = join(artifactDirectory, 'BOOLEAN-INVENTORY.md');
const shellOrigin = 'https://wellsoffice.ceo.wellsfargo.com';
const shellPathPrefix = '/ceosignon/';
const shellSourceLimit = 19;
const featureMfeSources = [
  {
    sourceSet: 'feature-mfe',
    feature: 'user-profile',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/userprofilemanagementmfe/MFE_18199B69_86C2_4DD9_9D77_B264C110A5B2/assets/js/23685.bundle.f005320b0999b0d037d2.js'
  },
  {
    sourceSet: 'feature-mfe',
    feature: 'user-profile',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/userprofilemanagementmfe/MFE_18199B69_86C2_4DD9_9D77_B264C110A5B2/assets/js/99973.bundle.1992235788cd8e6760cc.js'
  },
  {
    sourceSet: 'feature-mfe',
    feature: 'terms-of-use',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/termsofusemfe/MFE_5F757533_72B3_4D1A_BDE2_3D59E432BE10/assets/js/25707.bundle.a9424d2d8f75ef271746.js'
  },
  {
    sourceSet: 'feature-mfe',
    feature: 'terms-of-use',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/termsofusemfe/MFE_5F757533_72B3_4D1A_BDE2_3D59E432BE10/assets/js/52388.bundle.a31ea4fb65b6117e9faa.js'
  },
  {
    sourceSet: 'feature-mfe',
    feature: 'terms-of-use',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/termsofusemfe/MFE_5F757533_72B3_4D1A_BDE2_3D59E432BE10/assets/js/15208.bundle.b2581fcf9159471308e7.js'
  },
  {
    sourceSet: 'feature-mfe',
    feature: 'terms-of-use',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/termsofusemfe/MFE_5F757533_72B3_4D1A_BDE2_3D59E432BE10/assets/js/7352.bundle.35d3f1dda4ab94b0e57f.js'
  }
];
const nestedFeatureMfeSources = [
  {
    sourceSet: 'nested-feature-mfe',
    feature: 'user-contact-details-state',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/90627.bundle.774396b5bb79244ed884.js'
  },
  {
    sourceSet: 'nested-feature-mfe',
    feature: 'user-contact-details-remove',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/8188.bundle.3f645d3bf26bce6ce01c.js'
  },
  {
    sourceSet: 'nested-feature-mfe',
    feature: 'user-contact-details-save',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/27366.bundle.36afe6c51807064f254b.js'
  },
  {
    sourceSet: 'nested-feature-mfe',
    feature: 'user-account-settings-state',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/useraccountsettingsmfe/APP_CEOPT_USERACCOUNTSETTINGSMFE/assets/js/45236.bundle.4cc2ec85192dfe378162.js'
  },
  {
    sourceSet: 'nested-feature-mfe',
    feature: 'user-account-settings-gates',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/useraccountsettingsmfe/APP_CEOPT_USERACCOUNTSETTINGSMFE/assets/js/83561.bundle.24f5cda3cc34209fd608.js'
  },
  {
    sourceSet: 'nested-feature-mfe',
    feature: 'user-account-settings-auto-access',
    url: 'https://wellsceomfes.ceo.wellsfargo.com/useraccountsettingsmfe/APP_CEOPT_USERACCOUNTSETTINGSMFE/assets/js/58815.bundle.69941a6616c07e61aa7c.js'
  }
];
const sourceLimit =
  shellSourceLimit + featureMfeSources.length + nestedFeatureMfeSources.length;
const perSourceLimit = 4 * 1024 * 1024;
const combinedLimit = 16 * 1024 * 1024;
const requestSpacingMs = 500;
const userAgent = 'BLANCHE-Public-Boolean-Inventory/0.1 (anonymous bounded acquisition)';
let lastRequestStartedAt = 0;

const baseline = JSON.parse(await readFile(baselinePath, 'utf8'));
const baselineShellSources = baseline.sourceAssessments ?? [];
if (baselineShellSources.length !== shellSourceLimit) {
  throw new Error(
    `Expected ${shellSourceLimit} retained shell sources, found ${baselineShellSources.length}.`
  );
}
const expectedSources = [
  ...baselineShellSources.map((source) => ({
    ...source,
    sourceSet: 'shell',
    feature: 'vantage-sign-on-shell'
  })),
  ...featureMfeSources,
  ...nestedFeatureMfeSources
];
const allowedSourceUrls = new Set(expectedSources.map((source) => source.url));

const sources = [];
let retainedBytes = 0;
for (const expected of expectedSources) {
  const sourceUrl = new URL(expected.url);
  assertAllowedSourceUrl(sourceUrl);
  const acquired = await fetchBounded(sourceUrl, Math.min(perSourceLimit, combinedLimit - retainedBytes));
  retainedBytes += acquired.bytes.length;
  if (retainedBytes > combinedLimit) throw new Error('Combined source limit exceeded.');
  const sha256 = createHash('sha256').update(acquired.bytes).digest('hex');
  if (expected.sha256 && sha256 !== expected.sha256) {
    throw new Error(`Hash drift for retained source ${sourceUrl.href}.`);
  }
  sources.push({
    url: sourceUrl.href,
    filename: sourceUrl.pathname.split('/').pop() || sourceUrl.pathname,
    sourceSet: expected.sourceSet,
    feature: expected.feature,
    status: acquired.status,
    contentType: acquired.contentType,
    byteLength: acquired.bytes.length,
    sha256,
    expectedSha256: expected.sha256 ?? null,
    baselineHashMatched: expected.sha256 ? sha256 === expected.sha256 : null,
    text: acquired.text
  });
}

const occurrences = [];
const dynamicBooleanBindings = [];
const consumerGuardEvidence = [];
const stateAndActionTokens = [];
const parseCoverage = [];

for (const source of sources) {
  const sourceFile = ts.createSourceFile(
    source.filename,
    source.text,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.JS
  );
  const modules = identifyWebpackModules(source.text);
  const aliases = collectPropertyAliases(sourceFile);
  const diagnostics = sourceFile.parseDiagnostics.map((diagnostic) => ({
    code: diagnostic.code,
    start: diagnostic.start ?? null,
    length: diagnostic.length ?? null,
    message: ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')
  }));
  parseCoverage.push({
    sourceUrl: source.url,
    filename: source.filename,
    byteLength: source.byteLength,
    webpackModuleCount: modules.length,
    parseDiagnosticCount: diagnostics.length,
    parseDiagnostics: diagnostics.slice(0, 20)
  });

  visit(sourceFile, (node) => {
    const booleanMatch = extractBooleanOccurrence(node, sourceFile, aliases);
    if (booleanMatch) {
      const offset = node.getStart(sourceFile);
      const moduleInfo = findModule(modules, offset);
      const context = describeContext(node, sourceFile, booleanMatch);
      const snippet = makeSnippet(source.text, offset, node.getEnd());
      const classification = classifyOccurrence({
        key: booleanMatch.key,
        source,
        moduleInfo,
        snippet,
        context
      });
      occurrences.push({
        key: booleanMatch.key,
        normalizedKey: normalizeKey(booleanMatch.key),
        propertyPath: context.propertyPath,
        value: booleanMatch.value,
        rawExpression: booleanMatch.rawExpression,
        syntax: booleanMatch.syntax,
        origin: booleanMatch.origin,
        defaultSubject: booleanMatch.defaultSubject ?? null,
        roles: context.roles,
        classification: classification.value,
        classificationRationale: classification.rationale,
        sourceUrl: source.url,
        sourceFilename: source.filename,
        sourceSet: source.sourceSet,
        feature: source.feature,
        chunkId: chunkIdFromFilename(source.filename),
        moduleId: moduleInfo?.id ?? null,
        moduleClassification: moduleInfo?.classification ?? null,
        sourceOffset: offset,
        moduleOffset: moduleInfo ? offset - moduleInfo.start : null,
        line: sourceFile.getLineAndCharacterOfPosition(offset).line + 1,
        column: sourceFile.getLineAndCharacterOfPosition(offset).character + 1,
        functionName: context.functionName,
        switchCase: context.switchCase,
        containingVariable: context.containingVariable,
        snippet
      });
    }

    const dynamicBinding = extractDynamicBooleanBinding(node, sourceFile, aliases);
    if (dynamicBinding) {
      const offset = node.getStart(sourceFile);
      const moduleInfo = findModule(modules, offset);
      const snippet = makeSnippet(source.text, offset, node.getEnd());
      const control = describeControl(node, sourceFile);
      dynamicBooleanBindings.push({
        key: dynamicBinding.key,
        valueExpression: dynamicBinding.valueExpression,
        referencedKey: dynamicBinding.referencedKey,
        referencedKeys: dynamicBinding.referencedKeys,
        sourceUrl: source.url,
        sourceFilename: source.filename,
        sourceSet: source.sourceSet,
        feature: source.feature,
        chunkId: chunkIdFromFilename(source.filename),
        moduleId: moduleInfo?.id ?? null,
        moduleClassification: moduleInfo?.classification ?? null,
        sourceOffset: offset,
        moduleOffset: moduleInfo ? offset - moduleInfo.start : null,
        line: sourceFile.getLineAndCharacterOfPosition(offset).line + 1,
        column: sourceFile.getLineAndCharacterOfPosition(offset).character + 1,
        controlType: control.controlType,
        testId: control.testId,
        controlValue: control.controlValue,
        snippet
      });
    }

    if (
      ts.isIfStatement(node) &&
      (source.sourceSet === 'feature-mfe' || source.sourceSet === 'nested-feature-mfe')
    ) {
      const references = collectExpressionReferences(
        node.expression,
        node,
        sourceFile,
        aliases
      );
      const snippet = makeSnippet(source.text, node.getStart(sourceFile), node.thenStatement.getEnd());
      if (
        references.some((reference) =>
          /(?:perusal|authoriz|autoAccess|eSign|sso|confirm|submit|save|remove|userSelected|showSuccess|validate|loading|progress)/iu.test(
            reference
          )
        ) ||
        /(?:perusal|authoriz|auto.?access|e-?sign|sso|confirm|submit|save|remove)/iu.test(
          snippet
        )
      ) {
        const offset = node.getStart(sourceFile);
        const moduleInfo = findModule(modules, offset);
        consumerGuardEvidence.push({
          condition: truncate(node.expression.getText(sourceFile), 240),
          referencedKeys: references,
          guardType: containsReturnStatement(node.thenStatement)
            ? 'early-return'
            : 'conditional-branch',
          sourceUrl: source.url,
          sourceFilename: source.filename,
          sourceSet: source.sourceSet,
          feature: source.feature,
          chunkId: chunkIdFromFilename(source.filename),
          moduleId: moduleInfo?.id ?? null,
          moduleClassification: moduleInfo?.classification ?? null,
          sourceOffset: offset,
          moduleOffset: moduleInfo ? offset - moduleInfo.start : null,
          line: sourceFile.getLineAndCharacterOfPosition(offset).line + 1,
          column: sourceFile.getLineAndCharacterOfPosition(offset).character + 1,
          snippet
        });
      }
    }

    if (isStringLike(node) && /^[A-Z][A-Z0-9_]{3,}$/u.test(node.text)) {
      const offset = node.getStart(sourceFile);
      const moduleInfo = findModule(modules, offset);
      const snippet = makeSnippet(source.text, offset, node.getEnd());
      const tokenContext = describeTokenContext(node, sourceFile);
      const classification = classifyToken(node.text, source, moduleInfo, snippet);
      stateAndActionTokens.push({
        token: node.text,
        classification: classification.value,
        classificationRationale: classification.rationale,
        boundName: tokenContext.boundName,
        sourceUrl: source.url,
        sourceFilename: source.filename,
        chunkId: chunkIdFromFilename(source.filename),
        moduleId: moduleInfo?.id ?? null,
        moduleClassification: moduleInfo?.classification ?? null,
        sourceOffset: offset,
        moduleOffset: moduleInfo ? offset - moduleInfo.start : null,
        line: sourceFile.getLineAndCharacterOfPosition(offset).line + 1,
        column: sourceFile.getLineAndCharacterOfPosition(offset).character + 1,
        snippet
      });
    }
  });
}

const deduplicatedOccurrences = deduplicateOccurrences(occurrences);
const keys = aggregateBooleanKeys(deduplicatedOccurrences);
const environmentMaps = extractEnvironmentMaps(sources);
const actionTokens = aggregateTokens(stateAndActionTokens);
const deduplicatedDynamicBindings = deduplicateDynamicBindings(dynamicBooleanBindings);
const perusalControlBindings = deduplicatedDynamicBindings.filter(
  (entry) =>
    entry.feature === 'terms-of-use' &&
    entry.key === 'disabled' &&
    (entry.referencedKeys ?? []).some((reference) => /perusal/iu.test(reference))
);
const deduplicatedConsumerGuards = deduplicateConsumerGuards(consumerGuardEvidence);
const appBusinessKeys = keys
  .filter((entry) => entry.classificationCounts['app-business'] > 0)
  .map((entry) => entry.key);
const libraryRuntimeKeys = keys
  .filter((entry) => entry.classificationCounts['library-runtime'] > 0)
  .map((entry) => entry.key);
const mixedKeys = keys
  .filter(
    (entry) =>
      entry.classificationCounts['app-business'] > 0 &&
      entry.classificationCounts['library-runtime'] > 0
  )
  .map((entry) => entry.key);
const dualValuedKeys = keys.filter(
  (entry) => entry.observedValues.includes(true) && entry.observedValues.includes(false)
);
const reducerStateKeys = keys.filter((entry) =>
  entry.roles.some((role) => ['reducer-state', 'switch-case-update'].includes(role))
);
const reviewedVantageOccurrences = deduplicatedOccurrences.filter(isReviewedVantageOccurrence);
const reviewedVantageKeys = aggregateBooleanKeys(reviewedVantageOccurrences);
const reviewedVantageDynamicBindings = deduplicatedDynamicBindings.filter(
  (entry) =>
    entry.sourceSet === 'nested-feature-mfe' ||
    (entry.sourceFilename === '15208.bundle.b2581fcf9159471308e7.js' &&
      [7508, 12204, 70507].includes(entry.moduleId)) ||
    (entry.sourceFilename === '99973.bundle.1992235788cd8e6760cc.js' &&
      [48712, 56203, 64738, 80326, 99973].includes(entry.moduleId))
);

const report = {
  kind: 'blanche.public-boolean-configuration-inventory',
  generatedAt: new Date().toISOString(),
  collection: {
    mode: 'anonymous-public-read',
    credentialsSent: false,
    formsSubmitted: false,
    storageModified: false,
    nonProductionHostsContacted: false,
    allowedProductionOrigins: [...new Set(expectedSources.map((source) => new URL(source.url).origin))],
    exactSourceAllowlistEnforced: true,
    baselineArtifact: 'blanche-feature-map-audit.json',
    sourceCount: sources.length,
    shellSourceCount: sources.filter((source) => source.sourceSet === 'shell').length,
    featureMfeSourceCount: sources.filter((source) => source.sourceSet === 'feature-mfe').length,
    nestedFeatureMfeSourceCount: sources.filter(
      (source) => source.sourceSet === 'nested-feature-mfe'
    ).length,
    retainedBytes,
    limits: {
      sources: sourceLimit,
      bytesPerSource: perSourceLimit,
      combinedBytes: combinedLimit,
      requestStartSpacingMs: requestSpacingMs
    }
  },
  method: {
    parser: `TypeScript ${ts.version}`,
    staticFormsIncluded: [
      'object fields assigned true/false',
      'object fields assigned !0/!1',
      'property assignments assigned static booleans',
      'semantic variable and parameter defaults assigned static booleans',
      'conditional, nullish, and logical boolean defaults',
      'boolean reducer/switch-case object updates',
      'dynamic boolean-shaped UI control bindings',
      'literal production-delivered environment maps',
      'uppercase state/action/status string tokens'
    ],
    offsetUnits: 'UTF-16 code units from the start of each retained source',
    deduplication:
      'Boolean fields are grouped by exact key. Identical evidence occurrences are removed; all distinct values and evidence locations remain.',
    classification:
      'Heuristic separation using source/module provenance, semantic field names, and nearby application or library signatures. Mixed keys retain occurrence-level labels.',
    caveat:
      'A false default, reducer state, UI option, or library descriptor is not proof that a product feature is globally disabled. Runtime responses, server layouts, entitlements, and later state transitions can change values.'
  },
  summary: {
    booleanOccurrenceCount: deduplicatedOccurrences.length,
    uniqueKeyCount: keys.length,
    appBusinessOccurrenceCount: deduplicatedOccurrences.filter(
      (entry) => entry.classification === 'app-business'
    ).length,
    libraryRuntimeOccurrenceCount: deduplicatedOccurrences.filter(
      (entry) => entry.classification === 'library-runtime'
    ).length,
    appBusinessKeyCount: appBusinessKeys.length,
    libraryRuntimeKeyCount: libraryRuntimeKeys.length,
    mixedKeyCount: mixedKeys.length,
    dualValuedKeyCount: dualValuedKeys.length,
    reducerStateKeyCount: reducerStateKeys.length,
    environmentMapCount: environmentMaps.length,
    stateAndActionTokenCount: actionTokens.length,
    dynamicBooleanBindingCount: deduplicatedDynamicBindings.length,
    perusalControlBindingCount: perusalControlBindings.length,
    consumerGuardEvidenceCount: deduplicatedConsumerGuards.length,
    reviewedVantageOccurrenceCount: reviewedVantageOccurrences.length,
    reviewedVantageKeyCount: reviewedVantageKeys.length,
    parserDiagnosticCount: parseCoverage.reduce(
      (sum, entry) => sum + entry.parseDiagnosticCount,
      0
    )
  },
  classificationIndex: {
    appBusinessKeys,
    libraryRuntimeKeys,
    mixedKeys
  },
  reviewedVantageOwnedSubset: {
    criteria: [
      'Vantage sign-on reducer module 80288 in chunk 90460',
      'Vantage sign-on application module 27597 in chunk 69453',
      'reviewed Terms-of-Use application/state modules 7508, 12204, and 70507 in chunk 15208',
      'reviewed User Profile application/state modules 48712, 56203, 64738, 80326, and 99973 in chunk 99973',
      'semantic fields in the six explicitly allowlisted nested contact/account consumer chunks, excluding modules with strong library signatures'
    ],
    occurrenceCount: reviewedVantageOccurrences.length,
    uniqueKeyCount: reviewedVantageKeys.length,
    keys: reviewedVantageKeys,
    dynamicBooleanBindings: reviewedVantageDynamicBindings
  },
  dualValuedKeys: dualValuedKeys.map(summarizeKey),
  reducerAndStateKeys: reducerStateKeys.map(summarizeKey),
  environmentMaps,
  dynamicBooleanBindings: deduplicatedDynamicBindings,
  perusalControlBindings,
  consumerGuardEvidence: deduplicatedConsumerGuards,
  stateAndActionTokens: actionTokens,
  booleanKeys: keys,
  sourceCoverage: sources.map(({ text, ...source }) => source),
  parseCoverage
};

const markdown = renderMarkdown(report);
await writeFile(jsonOutputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
await writeFile(markdownOutputPath, markdown, 'utf8');

process.stdout.write(
  `${JSON.stringify(
    {
      jsonOutputPath,
      markdownOutputPath,
      collection: report.collection,
      summary: report.summary
    },
    null,
    2
  )}\n`
);

function assertAllowedSourceUrl(url) {
  if (!allowedSourceUrls.has(url.href)) {
    throw new Error(`Refusing out-of-scope source URL: ${url.href}`);
  }
}

async function fetchBounded(url, maxBytes) {
  if (maxBytes <= 0) throw new Error('Combined source limit reached.');
  let response;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const waitMs = Math.max(
      0,
      requestSpacingMs - (Date.now() - lastRequestStartedAt),
      attempt > 1 ? attempt * 500 : 0
    );
    if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
    lastRequestStartedAt = Date.now();
    response = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        accept: 'application/javascript,text/javascript,*/*;q=0.1',
        'user-agent': userAgent
      }
    });
    if (response.status !== 429 && response.status < 500) break;
    if (response.body) await response.body.cancel();
  }
  if (!response) throw new Error(`No response from ${url.href}.`);
  if (response.status >= 300 && response.status < 400) {
    throw new Error(`Refusing redirect while acquiring retained source ${url.href}.`);
  }
  if (!response.ok) throw new Error(`HTTP ${response.status} from ${url.href}.`);
  if (!response.body) throw new Error(`Empty response body from ${url.href}.`);
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    if (length + chunk.length > maxBytes) {
      await reader.cancel();
      throw new Error(`Source exceeded bounded acquisition limit: ${url.href}.`);
    }
    chunks.push(chunk);
    length += chunk.length;
  }
  const bytes = Buffer.concat(chunks, length);
  return {
    status: response.status,
    contentType: response.headers.get('content-type'),
    bytes,
    text: new TextDecoder().decode(bytes)
  };
}

function visit(node, callback) {
  callback(node);
  ts.forEachChild(node, (child) => visit(child, callback));
}

function collectPropertyAliases(sourceFile) {
  const aliases = [];
  visit(sourceFile, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
    const directPropertyKey = expressionPropertyKey(node.initializer);
    const propertyKey =
      directPropertyKey && isSemanticIdentifier(directPropertyKey) && !/^\d+$/u.test(directPropertyKey)
        ? directPropertyKey
        : findSemanticPropertyReference(node.initializer);
    if (!propertyKey) return;
    const scope = nearestScope(node, sourceFile);
    aliases.push({
      identifier: node.name.text,
      propertyKey,
      start: node.getStart(sourceFile),
      scopeStart: scope.getStart(sourceFile),
      scopeEnd: scope.getEnd()
    });
  });
  return aliases;
}

function findSemanticPropertyReference(expression) {
  const candidates = [];
  const scan = (node) => {
    if (ts.isPropertyAccessExpression(node)) {
      const name = node.name.text;
      if (
        /^(?:is|has|can|should|show|hide|enable|disable|allow|use|authorized|perusal|loading|status|validate|confirm|autoAccess|eSign|sso)[A-Za-z0-9_]*$/u.test(
          name
        )
      ) {
        candidates.push(name);
      }
    }
    ts.forEachChild(node, scan);
  };
  scan(expression);
  return candidates.at(-1) ?? null;
}

function nearestScope(node, sourceFile) {
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isFunctionLike(current) || ts.isSourceFile(current)) return current;
  }
  return sourceFile;
}

function resolveAlias(identifier, node, sourceFile, aliases) {
  const offset = node.getStart(sourceFile);
  const candidates = aliases
    .filter(
      (entry) =>
        entry.identifier === identifier &&
        entry.start <= offset &&
        entry.scopeStart <= offset &&
        entry.scopeEnd >= offset
    )
    .sort(
      (left, right) =>
        right.scopeStart - left.scopeStart || right.start - left.start
    );
  return candidates[0]?.propertyKey ?? null;
}

function extractBooleanOccurrence(node, sourceFile, aliases) {
  if (ts.isPropertyAssignment(node)) {
    const key = propertyNameText(node.name, sourceFile);
    const match = staticBoolean(node.initializer, sourceFile);
    if (key && match) return makeBooleanMatch(key, match, 'object-field', node.initializer, sourceFile);
  }

  if (ts.isShorthandPropertyAssignment(node) && node.objectAssignmentInitializer) {
    const match = staticBoolean(node.objectAssignmentInitializer, sourceFile);
    if (match) {
      return makeBooleanMatch(
        node.name.text,
        match,
        'shorthand-object-default',
        node.objectAssignmentInitializer,
        sourceFile
      );
    }
  }

  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.EqualsToken
  ) {
    const key = assignmentTargetKey(node.left, sourceFile);
    const match = staticBoolean(node.right, sourceFile);
    if (key && match) return makeBooleanMatch(key, match, 'property-assignment', node.right, sourceFile);
  }

  if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
    const match = staticBoolean(node.initializer, sourceFile);
    if (!match) return null;
    const subject = match.defaultSubject;
    const aliasKey = subject
      ? resolveAlias(subject, node, sourceFile, aliases) ?? expressionKeyFromText(subject)
      : null;
    const key = aliasKey || (isSemanticIdentifier(node.name.text) ? node.name.text : null);
    if (key) return makeBooleanMatch(key, match, 'variable-default', node.initializer, sourceFile);
  }

  if (ts.isParameter(node) && ts.isIdentifier(node.name) && node.initializer) {
    const match = staticBoolean(node.initializer, sourceFile);
    if (match) return makeBooleanMatch(node.name.text, match, 'parameter-default', node.initializer, sourceFile);
  }

  if (ts.isBindingElement(node) && node.initializer) {
    const match = staticBoolean(node.initializer, sourceFile);
    if (!match) return null;
    const key = node.propertyName
      ? propertyNameText(node.propertyName, sourceFile)
      : ts.isIdentifier(node.name)
        ? node.name.text
        : null;
    if (key) return makeBooleanMatch(key, match, 'destructuring-default', node.initializer, sourceFile);
  }

  if (ts.isPropertyDeclaration(node) && node.initializer) {
    const key = propertyNameText(node.name, sourceFile);
    const match = staticBoolean(node.initializer, sourceFile);
    if (key && match) return makeBooleanMatch(key, match, 'class-field', node.initializer, sourceFile);
  }

  return null;
}

function extractDynamicBooleanBinding(node, sourceFile, aliases) {
  if (!ts.isPropertyAssignment(node)) return null;
  const key = propertyNameText(node.name, sourceFile);
  if (!key || !isBooleanShapedKey(key) || staticBoolean(node.initializer, sourceFile)) return null;
  const expression = unwrapExpression(node.initializer);
  const directReference = expressionReference(expression, sourceFile);
  const referencedKeys = collectExpressionReferences(expression, node, sourceFile, aliases);
  const referencedKey =
    referencedKeys.length === 1
      ? referencedKeys[0]
      : referencedKeys.length > 1
        ? referencedKeys.join(' | ')
        : directReference;
  return {
    key,
    valueExpression: truncate(expression.getText(sourceFile), 160),
    referencedKey,
    referencedKeys
  };
}

function collectExpressionReferences(expression, ownerNode, sourceFile, aliases) {
  const references = [];
  const scan = (node) => {
    if (ts.isPropertyAccessExpression(node)) {
      references.push(node.name.text);
      const base = unwrapExpression(node.expression);
      if (ts.isIdentifier(base)) {
        references.push(resolveAlias(base.text, ownerNode, sourceFile, aliases) ?? base.text);
      } else {
        scan(base);
      }
      return;
    }
    if (ts.isIdentifier(node)) {
      const resolved = resolveAlias(node.text, ownerNode, sourceFile, aliases);
      references.push(resolved ?? node.text);
      return;
    }
    ts.forEachChild(node, scan);
  };
  scan(expression);
  return [...new Set(references.filter(Boolean))];
}

function containsReturnStatement(node) {
  let found = false;
  const scan = (current) => {
    if (found) return;
    if (ts.isReturnStatement(current)) {
      found = true;
      return;
    }
    if (ts.isFunctionLike(current) && current !== node) return;
    ts.forEachChild(current, scan);
  };
  scan(node);
  return found;
}

function isBooleanShapedKey(key) {
  return /^(?:disabled|checked|selected|hidden|readOnly|required|multiple|open|active|visible|expanded|pressed|busy|invalid|is[A-Z_].*|has[A-Z_].*|can[A-Z_].*|should[A-Z_].*|show[A-Z_].*|hide[A-Z_].*|enable[A-Z_].*|disable[A-Z_].*|allow[A-Z_].*|use[A-Z_].*)$/u.test(
    key
  );
}

function describeControl(node, sourceFile) {
  for (let current = node.parent; current; current = current.parent) {
    if (!ts.isObjectLiteralExpression(current)) continue;
    const call = current.parent;
    if (!call || !ts.isCallExpression(call) || call.arguments[1] !== current) continue;
    const controlType = call.arguments[0]
      ? truncate(call.arguments[0].getText(sourceFile), 100)
      : null;
    let testId = null;
    let controlValue = null;
    for (const property of current.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const propertyKey = propertyNameText(property.name, sourceFile);
      if (propertyKey === 'data-testid' && isStringLike(property.initializer)) {
        testId = property.initializer.text;
      }
      if (propertyKey === 'value' && isStringLike(property.initializer)) {
        controlValue = property.initializer.text;
      }
    }
    return { controlType, testId, controlValue };
  }
  return { controlType: null, testId: null, controlValue: null };
}

function makeBooleanMatch(key, match, origin, expression, sourceFile) {
  return {
    key,
    value: match.value,
    syntax: match.syntax,
    defaultSubject: match.defaultSubject ?? null,
    origin,
    rawExpression: truncate(expression.getText(sourceFile), 120)
  };
}

function staticBoolean(node, sourceFile) {
  const expression = unwrapExpression(node);
  if (expression.kind === ts.SyntaxKind.TrueKeyword) {
    return { value: true, syntax: 'literal-true' };
  }
  if (expression.kind === ts.SyntaxKind.FalseKeyword) {
    return { value: false, syntax: 'literal-false' };
  }
  if (
    ts.isPrefixUnaryExpression(expression) &&
    expression.operator === ts.SyntaxKind.ExclamationToken
  ) {
    const operand = unwrapExpression(expression.operand);
    if (ts.isNumericLiteral(operand) && (operand.text === '0' || operand.text === '1')) {
      return {
        value: operand.text === '0',
        syntax: operand.text === '0' ? 'minified-!0' : 'minified-!1'
      };
    }
    const nested = staticBoolean(operand, sourceFile);
    if (nested && !nested.defaultSubject) {
      return { value: !nested.value, syntax: `negated-${nested.syntax}` };
    }
  }
  if (ts.isConditionalExpression(expression)) {
    const whenTrue = staticBoolean(expression.whenTrue, sourceFile);
    const whenFalse = staticBoolean(expression.whenFalse, sourceFile);
    if (whenTrue && !whenFalse) {
      return {
        value: whenTrue.value,
        syntax: `conditional-default:${whenTrue.syntax}`,
        defaultSubject: expressionReference(expression.whenFalse, sourceFile)
      };
    }
    if (!whenTrue && whenFalse) {
      return {
        value: whenFalse.value,
        syntax: `conditional-default:${whenFalse.syntax}`,
        defaultSubject: expressionReference(expression.whenTrue, sourceFile)
      };
    }
    if (whenTrue && whenFalse && whenTrue.value === whenFalse.value) {
      return { value: whenTrue.value, syntax: 'conditional-static' };
    }
  }
  if (ts.isBinaryExpression(expression)) {
    const operator = expression.operatorToken.kind;
    if (
      operator === ts.SyntaxKind.QuestionQuestionToken ||
      operator === ts.SyntaxKind.BarBarToken ||
      operator === ts.SyntaxKind.AmpersandAmpersandToken
    ) {
      const right = staticBoolean(expression.right, sourceFile);
      if (right) {
        const label =
          operator === ts.SyntaxKind.QuestionQuestionToken
            ? 'nullish-default'
            : operator === ts.SyntaxKind.BarBarToken
              ? 'logical-or-default'
              : 'logical-and-default';
        return {
          value: right.value,
          syntax: `${label}:${right.syntax}`,
          defaultSubject: expressionReference(expression.left, sourceFile)
        };
      }
    }
  }
  return null;
}

function unwrapExpression(node) {
  let current = node;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current) ||
    (ts.isSatisfiesExpression && ts.isSatisfiesExpression(current))
  ) {
    current = current.expression;
  }
  return current;
}

function expressionReference(node, sourceFile) {
  const expression = unwrapExpression(node);
  if (ts.isIdentifier(expression)) return expression.text;
  const property = expressionPropertyKey(expression);
  if (property) return property;
  return truncate(expression.getText(sourceFile), 80);
}

function expressionPropertyKey(node) {
  const expression = unwrapExpression(node);
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression) {
    const argument = unwrapExpression(expression.argumentExpression);
    if (isStringLike(argument) || ts.isNumericLiteral(argument)) return argument.text;
  }
  return null;
}

function expressionKeyFromText(value) {
  if (/^[A-Za-z_$][\w$]*$/u.test(value) && isSemanticIdentifier(value)) return value;
  const match = value.match(/(?:^|\.)([A-Za-z_$][\w$]*)$/u);
  return match?.[1] ?? null;
}

function assignmentTargetKey(node, sourceFile) {
  const target = unwrapExpression(node);
  if (ts.isPropertyAccessExpression(target)) return target.name.text;
  if (ts.isElementAccessExpression(target) && target.argumentExpression) {
    const argument = unwrapExpression(target.argumentExpression);
    if (isStringLike(argument) || ts.isNumericLiteral(argument)) return argument.text;
  }
  if (ts.isIdentifier(target) && isSemanticIdentifier(target.text)) return target.text;
  return null;
}

function propertyNameText(node, sourceFile) {
  if (ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) return node.text;
  if (isStringLike(node) || ts.isNumericLiteral(node)) return node.text;
  if (ts.isComputedPropertyName(node)) {
    const expression = unwrapExpression(node.expression);
    if (isStringLike(expression) || ts.isNumericLiteral(expression)) return expression.text;
    return `[${truncate(expression.getText(sourceFile), 80)}]`;
  }
  return null;
}

function isStringLike(node) {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node);
}

function isSemanticIdentifier(value) {
  return value.length >= 3 || value.includes('_') || /[A-Z]/u.test(value);
}

function identifyWebpackModules(text) {
  const starts = [];
  const pattern = /(?:^|[,{])(\d+):(?:function\([^)]*\)|\([^)]*\)=>|[A-Za-z_$][\w$]*=>)\{/gu;
  for (const match of text.matchAll(pattern)) {
    const idOffset = (match.index ?? 0) + match[0].indexOf(match[1]);
    starts.push({ id: Number(match[1]), start: idOffset });
  }
  return starts.map((entry, index) => {
    const end = starts[index + 1]?.start ?? text.length;
    return {
      ...entry,
      end,
      classification: classifyModuleText(text.slice(entry.start, end))
    };
  });
}

function classifyModuleText(moduleText) {
  const librarySignatures = [
    /AxiosError|isAxiosError|toFormData|formDataToJSON|ERR_BAD_(?:OPTION|RESPONSE)|ERR_NETWORK/u,
    /react\.production|minified React error|ReactCurrentDispatcher|react\.element/u,
    /checkPropTypes|prop-types|ReactPropTypesSecret/u,
    /redux|createStore|combineReducers|observable/u,
    /regeneratorRuntime|Generator is already running|iterator result is not an object/u,
    /lodash|core-js|polyfill|Symbol\.iterator/u,
    /Buffer\.from|SlowBuffer|INSPECT_MAX_BYTES|Uint8Array/u,
    /IntlMessageFormat|defaultLocale|pluralRuleFunction/u,
    /fast-xml-parser|removeNSPrefix|parseTagValue|ignoreAttributes/u,
    /Object\.defineProperty|__esModule/u
  ];
  const appSignatures = [
    /Vantage|CEO_LOGIN|CEOPT/u,
    /termsOfUse|recordToUResponse|isPerusal/u,
    /forgotPassword|newUser|signOn|AccountUnlock/u,
    /companyId|userId|userProfile|contactDetails/u,
    /CAAS|RSAToken|PWCPage|ConsentPXP|SVPage/u,
    /ExperienceLayout|remoteEntry\.js/u
  ];
  const libraryScore = librarySignatures.reduce(
    (score, pattern) => score + (pattern.test(moduleText) ? 1 : 0),
    0
  );
  const appScore = appSignatures.reduce(
    (score, pattern) => score + (pattern.test(moduleText) ? 1 : 0),
    0
  );
  if (libraryScore >= 2 && libraryScore >= appScore) return 'library-runtime';
  if (appScore >= 2 && appScore > libraryScore) return 'app-business';
  return 'unknown';
}

function findModule(modules, offset) {
  let low = 0;
  let high = modules.length - 1;
  let match = null;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    if (modules[middle].start <= offset) {
      match = modules[middle];
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return match && offset < match.end ? match : null;
}

function describeContext(node, sourceFile, booleanMatch) {
  const propertyParts = [];
  let functionName = null;
  let switchCase = null;
  let containingVariable = null;
  let reducerSwitch = false;
  let reducerContainer = false;
  let componentDefault = false;
  let createElementProp = false;
  for (let current = node; current; current = current.parent) {
    if (ts.isPropertyAssignment(current)) {
      const name = propertyNameText(current.name, sourceFile);
      if (name) propertyParts.unshift(name);
    }
    if (!containingVariable && ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) {
      containingVariable = current.name.text;
    }
    if (!functionName && ts.isFunctionLike(current)) functionName = inferFunctionName(current, sourceFile);
    if (!switchCase && (ts.isCaseClause(current) || ts.isDefaultClause(current))) {
      switchCase = ts.isCaseClause(current)
        ? truncate(current.expression.getText(sourceFile), 100)
        : 'default';
      const switchStatement = current.parent?.parent;
      if (switchStatement && ts.isSwitchStatement(switchStatement)) {
        const discriminant = switchStatement.expression.getText(sourceFile);
        reducerSwitch =
          /(?:^|\.)(?:type|actionType)$/iu.test(discriminant) ||
          /(?:action|payload)\.type/iu.test(discriminant);
      }
    }
    if (
      ts.isBinaryExpression(current) &&
      current.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      /(?:^|\.)defaultProps$/u.test(current.left.getText(sourceFile))
    ) {
      componentDefault = true;
    }
    if (
      ts.isCallExpression(current) &&
      /(?:^|\.)createElement$/u.test(current.expression.getText(sourceFile)) &&
      current.arguments[1] &&
      containsNode(current.arguments[1], node)
    ) {
      createElementProp = true;
    }
    if (
      ts.isCallExpression(current) &&
      /(?:^|\.)addCase$/u.test(current.expression.getText(sourceFile))
    ) {
      reducerContainer = true;
    }
  }
  if (propertyParts.some((part) => /^(?:initialState|reducers|extraReducers)$/u.test(part))) {
    reducerContainer = true;
  }
  const roles = [];
  if (booleanMatch.syntax.includes('default') || booleanMatch.origin.includes('default')) roles.push('default');
  if (reducerSwitch) roles.push('switch-case-update');
  if (
    reducerSwitch ||
    reducerContainer ||
    /reducer/iu.test(functionName ?? '') ||
    /reducer/iu.test(containingVariable ?? '')
  ) {
    roles.push('reducer-state');
  }
  if (componentDefault) roles.push('component-default');
  if (createElementProp) roles.push('component-prop');
  if (/^(?:is|has|can|should|show|hide|enable|disable|allow|use)[A-Z_]/u.test(booleanMatch.key)) {
    roles.push('boolean-option');
  }
  if (propertyParts.some((part) => /^(?:prd|fix|uat|sit|dev|hos|local)$/iu.test(part))) {
    roles.push('environment-map-option');
  }
  if (roles.length === 0) roles.push('state-or-option');
  return {
    propertyPath: propertyParts.length ? propertyParts.join('.') : booleanMatch.key,
    functionName,
    switchCase,
    containingVariable,
    roles: [...new Set(roles)]
  };
}

function containsNode(container, node) {
  return container.pos <= node.pos && container.end >= node.end;
}

function inferFunctionName(node, sourceFile) {
  if ('name' in node && node.name) return propertyNameText(node.name, sourceFile);
  const parent = node.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  if (parent && ts.isPropertyAssignment(parent)) return propertyNameText(parent.name, sourceFile);
  if (parent && ts.isBinaryExpression(parent)) return truncate(parent.left.getText(sourceFile), 100);
  return null;
}

function classifyOccurrence({ key, source, moduleInfo, snippet, context }) {
  const filename = source.filename;
  const semanticKey = isSemanticIdentifier(key) && !/^[A-Za-z_$]$/u.test(key);
  const strongLibraryKey = /^(?:__esModule|enumerable|configurable|writable|loaded|loading|eager|async|passive|capture|once|bubbles|cancelable|composed|writableEnded|destroyed|readable|writableObjectMode|readableObjectMode|allowHalfOpen|decodeStrings|objectMode|emitClose|autoDestroy|construct|sync|enumerableOwnProperties|ignoreCase|dotAll|multiline|sticky|unicode|global)$/iu.test(
    key
  );
  const businessKey = /(?:auth|captcha|company|user|password|passcode|token|profile|feedback|confirm|redirect|country|signon|login|cookie|perusal|entitlement|register|enroll|mfa|rsa|secureValidation|newUser|softToken|hardToken|terms|consent|flow|step|form|mobile|banner|platform|layout|session|account|support)/iu.test(
    key
  );
  const appSource =
    source.sourceSet === 'feature-mfe' ||
    source.sourceSet === 'nested-feature-mfe' ||
    /^(?:44985|73470|90460|71297|8030|69453)\./u.test(filename);
  const definitiveAppSource = /^(?:90460|71297|8030)\./u.test(filename);
  const localContext = `${key} ${snippet} ${context.functionName ?? ''} ${context.containingVariable ?? ''}`;
  const appSignature = /(?:Vantage|forgotPassword|newUser|signOn|AccountUnlock|CAAS|captcha|companyId|userId|PWCPage|RSAToken|ConsentPXP|SVPage|CEO_LOGIN|ExperienceLayout)/u.test(
    localContext
  );
  const librarySignature = /(?:webpack|PropTypes|React|redux|axios|lodash|Intl|Buffer|Object\.defineProperty|prototype|Symbol|regenerator|polyfill)/iu.test(
    localContext
  );
  if (strongLibraryKey) {
    return { value: 'library-runtime', rationale: 'well-known runtime/library metadata key' };
  }
  if (moduleInfo?.classification === 'library-runtime') {
    return { value: 'library-runtime', rationale: 'Webpack module has strong library implementation signatures' };
  }
  if (/^[A-Z][a-zA-Z]$/u.test(key) || /^[a-zA-Z]$/u.test(key)) {
    return { value: 'library-runtime', rationale: 'minified local identifier without a stable semantic field name' };
  }
  if (moduleInfo?.classification === 'app-business' && semanticKey && !librarySignature) {
    return { value: 'app-business', rationale: 'Webpack module has strong application/business signatures' };
  }
  if (
    (definitiveAppSource ||
      source.sourceSet === 'feature-mfe' ||
      source.sourceSet === 'nested-feature-mfe') &&
    semanticKey &&
    !librarySignature
  ) {
    return { value: 'app-business', rationale: 'semantic field in an application state/configuration chunk' };
  }
  if (appSource && semanticKey && (businessKey || appSignature) && !librarySignature) {
    return { value: 'app-business', rationale: 'application-source field with business/authentication context' };
  }
  if (context.roles.includes('reducer-state') && appSource && semanticKey) {
    return { value: 'app-business', rationale: 'semantic reducer-state field in an application chunk' };
  }
  return {
    value: 'library-runtime',
    rationale: moduleInfo
      ? 'generic or library/runtime field without sufficient application-specific evidence'
      : 'bundle bootstrap/runtime field outside a confidently identified application module'
  };
}

function isReviewedVantageOccurrence(entry) {
  if (
    entry.sourceFilename === '90460.chunk.6fd8af48bf6f8fcdcfb0.js' &&
    entry.moduleId === 80288
  ) {
    return true;
  }
  if (
    entry.sourceFilename === '69453.chunk.36716f8b5afaaf4be835.js' &&
    entry.moduleId === 27597
  ) {
    return true;
  }
  if (
    entry.sourceFilename === '15208.bundle.b2581fcf9159471308e7.js' &&
    [7508, 12204, 70507].includes(entry.moduleId)
  ) {
    return true;
  }
  if (
    entry.sourceFilename === '99973.bundle.1992235788cd8e6760cc.js' &&
    [48712, 56203, 64738, 80326, 99973].includes(entry.moduleId)
  ) {
    return true;
  }
  return (
    entry.sourceSet === 'nested-feature-mfe' &&
    entry.moduleClassification !== 'library-runtime' &&
    isSemanticIdentifier(entry.key) &&
    !/^[A-Za-z]$/u.test(entry.key)
  );
}

function describeTokenContext(node, sourceFile) {
  const parent = node.parent;
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return { boundName: parent.name.text };
  }
  if (ts.isPropertyAssignment(parent)) {
    return { boundName: propertyNameText(parent.name, sourceFile) };
  }
  if (ts.isBinaryExpression(parent)) {
    return { boundName: truncate(parent.left.getText(sourceFile), 100) };
  }
  return { boundName: null };
}

function classifyToken(token, source, moduleInfo, snippet) {
  const businessToken = /(?:AUTH|LOGIN|SIGNON|PASSWORD|PASSCODE|TOKEN|PROFILE|USER|COMPANY|CAPTCHA|REGISTER|ENROLL|MFA|RSA|CONSENT|NEW_USER|FORGOT|RESET|ACCOUNT|SESSION|FLOW|FEEDBACK|CONFIRM|REDIRECT|TERMS|SV_|CAAS|PWC)/u.test(
    token
  );
  const appSource =
    source.sourceSet === 'feature-mfe' ||
    source.sourceSet === 'nested-feature-mfe' ||
    /^(?:44985|73470|90460|71297|8030|69453)\./u.test(source.filename);
  if (businessToken && (appSource || /Vantage|signOn|forgotPassword/u.test(snippet))) {
    return { value: 'app-business', rationale: 'authentication/business state or action token' };
  }
  return {
    value: 'library-runtime',
    rationale: moduleInfo
      ? 'generic uppercase token in a bundled module'
      : 'generic uppercase token in bundle runtime'
  };
}

function deduplicateOccurrences(entries) {
  const seen = new Map();
  for (const entry of entries) {
    const identity = [
      entry.sourceUrl,
      entry.sourceOffset,
      entry.key,
      entry.value,
      entry.origin,
      entry.syntax
    ].join('|');
    if (!seen.has(identity)) seen.set(identity, entry);
  }
  return [...seen.values()].sort(
    (left, right) =>
      left.key.localeCompare(right.key) ||
      left.sourceUrl.localeCompare(right.sourceUrl) ||
      left.sourceOffset - right.sourceOffset
  );
}

function deduplicateDynamicBindings(entries) {
  const seen = new Map();
  for (const entry of entries) {
    const identity = [
      entry.sourceUrl,
      entry.sourceOffset,
      entry.key,
      entry.valueExpression,
      entry.referencedKey
    ].join('|');
    if (!seen.has(identity)) seen.set(identity, entry);
  }
  return [...seen.values()].sort(
    (left, right) =>
      left.key.localeCompare(right.key) ||
      (left.referencedKey ?? '').localeCompare(right.referencedKey ?? '') ||
      left.sourceUrl.localeCompare(right.sourceUrl) ||
      left.sourceOffset - right.sourceOffset
  );
}

function deduplicateConsumerGuards(entries) {
  const seen = new Map();
  for (const entry of entries) {
    const identity = [entry.sourceUrl, entry.sourceOffset, entry.condition].join('|');
    if (!seen.has(identity)) seen.set(identity, entry);
  }
  return [...seen.values()].sort(
    (left, right) =>
      left.sourceUrl.localeCompare(right.sourceUrl) || left.sourceOffset - right.sourceOffset
  );
}

function aggregateBooleanKeys(entries) {
  const groups = new Map();
  for (const entry of entries) {
    const group = groups.get(entry.key) ?? {
      key: entry.key,
      normalizedKey: entry.normalizedKey,
      totalCount: 0,
      observedValues: [],
      valueCounts: { true: 0, false: 0 },
      syntaxCounts: {},
      originCounts: {},
      classificationCounts: { 'app-business': 0, 'library-runtime': 0 },
      roles: [],
      sourceUrls: [],
      sourceFilenames: [],
      moduleIds: [],
      occurrences: []
    };
    group.totalCount += 1;
    group.valueCounts[String(entry.value)] += 1;
    group.syntaxCounts[entry.syntax] = (group.syntaxCounts[entry.syntax] ?? 0) + 1;
    group.originCounts[entry.origin] = (group.originCounts[entry.origin] ?? 0) + 1;
    group.classificationCounts[entry.classification] += 1;
    if (!group.observedValues.includes(entry.value)) group.observedValues.push(entry.value);
    for (const role of entry.roles) if (!group.roles.includes(role)) group.roles.push(role);
    if (!group.sourceUrls.includes(entry.sourceUrl)) group.sourceUrls.push(entry.sourceUrl);
    if (!group.sourceFilenames.includes(entry.sourceFilename)) {
      group.sourceFilenames.push(entry.sourceFilename);
    }
    if (entry.moduleId !== null && !group.moduleIds.includes(entry.moduleId)) {
      group.moduleIds.push(entry.moduleId);
    }
    group.occurrences.push(entry);
    groups.set(entry.key, group);
  }
  return [...groups.values()]
    .map((group) => ({
      ...group,
      observedValues: group.observedValues.sort(),
      roles: group.roles.sort(),
      sourceUrls: group.sourceUrls.sort(),
      sourceFilenames: group.sourceFilenames.sort(),
      moduleIds: group.moduleIds.sort((left, right) => left - right)
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
}

function summarizeKey(entry) {
  return {
    key: entry.key,
    observedValues: entry.observedValues,
    valueCounts: entry.valueCounts,
    totalCount: entry.totalCount,
    roles: entry.roles,
    classificationCounts: entry.classificationCounts,
    sourceFilenames: entry.sourceFilenames,
    moduleIds: entry.moduleIds
  };
}

function aggregateTokens(entries) {
  const groups = new Map();
  for (const entry of entries) {
    const group = groups.get(entry.token) ?? {
      token: entry.token,
      totalCount: 0,
      classificationCounts: { 'app-business': 0, 'library-runtime': 0 },
      boundNames: [],
      sourceFilenames: [],
      occurrences: []
    };
    group.totalCount += 1;
    group.classificationCounts[entry.classification] += 1;
    if (entry.boundName && !group.boundNames.includes(entry.boundName)) {
      group.boundNames.push(entry.boundName);
    }
    if (!group.sourceFilenames.includes(entry.sourceFilename)) {
      group.sourceFilenames.push(entry.sourceFilename);
    }
    group.occurrences.push(entry);
    groups.set(entry.token, group);
  }
  return [...groups.values()].sort((left, right) => left.token.localeCompare(right.token));
}

function extractEnvironmentMaps(sourceEntries) {
  const groups = new Map();
  const objectPattern = /([A-Za-z_$][A-Za-z0-9_$]{1,100})\s*:\s*\{([^{}]{1,4000})\}/gu;
  const environmentPattern = /(?:^|,)\s*(prd|fix|uat|sit|dev|hos|local)\s*:\s*(["'])(https?:\/\/.*?)\2/giu;
  for (const source of sourceEntries) {
    const modules = identifyWebpackModules(source.text);
    for (const objectMatch of source.text.matchAll(objectPattern)) {
      const environments = {};
      for (const environmentMatch of objectMatch[2].matchAll(environmentPattern)) {
        const environment = environmentMatch[1].toLowerCase();
        const rawUrl = environmentMatch[3].trim();
        try {
          const parsed = new URL(rawUrl);
          environments[environment] = {
            resourceUrl: rawUrl,
            hostname: parsed.hostname,
            contacted: false
          };
        } catch {
          environments[environment] = {
            resourceUrl: rawUrl,
            hostname: null,
            contacted: false
          };
        }
      }
      if (!environments.prd || Object.keys(environments).length < 2) continue;
      const mappingKey = objectMatch[1];
      const offset = objectMatch.index ?? 0;
      const moduleInfo = findModule(modules, offset);
      const variantKey = JSON.stringify(environments);
      const group = groups.get(mappingKey) ?? { mappingKey, variants: [] };
      let variant = group.variants.find((entry) => entry.variantKey === variantKey);
      if (!variant) {
        variant = { variantKey, environments, evidence: [] };
        group.variants.push(variant);
      }
      variant.evidence.push({
        sourceUrl: source.url,
        sourceFilename: source.filename,
        chunkId: chunkIdFromFilename(source.filename),
        moduleId: moduleInfo?.id ?? null,
        sourceOffset: offset,
        moduleOffset: moduleInfo ? offset - moduleInfo.start : null,
        snippet: makeSnippet(source.text, offset, offset + objectMatch[0].length)
      });
      groups.set(mappingKey, group);
    }
  }
  return [...groups.values()]
    .map((group) => ({
      mappingKey: group.mappingKey,
      variantCount: group.variants.length,
      variants: group.variants.map(({ variantKey, ...variant }) => variant)
    }))
    .sort((left, right) => left.mappingKey.localeCompare(right.mappingKey));
}

function normalizeKey(value) {
  return value.replace(/[^A-Za-z0-9]+/gu, '').toLowerCase();
}

function chunkIdFromFilename(filename) {
  const match = filename.match(/^(\d+)\.(?:chunk|bundle)\./u);
  return match ? Number(match[1]) : null;
}

function makeSnippet(text, start, end) {
  const before = 90;
  const after = 130;
  const snippetStart = Math.max(0, start - before);
  const snippetEnd = Math.min(text.length, Math.max(end, start) + after);
  return text
    .slice(snippetStart, snippetEnd)
    .replace(/\s+/gu, ' ')
    .trim();
}

function truncate(value, limit) {
  return value.length <= limit ? value : `${value.slice(0, limit - 1)}…`;
}

function renderMarkdown(value) {
  const appKeys = value.reviewedVantageOwnedSubset.keys
    .sort(
      (left, right) =>
        right.classificationCounts['app-business'] - left.classificationCounts['app-business'] ||
        left.key.localeCompare(right.key)
    );
  const dual = value.dualValuedKeys;
  const reducer = value.reducerAndStateKeys;
  const lines = [
    '# BLANCHE boolean/configuration inventory',
    '',
    `Generated: ${value.generatedAt}`,
    '',
    '## Scope and interpretation',
    '',
    `This inventory statically parsed ${value.collection.sourceCount} anonymous production JavaScript sources (${value.collection.retainedBytes.toLocaleString('en-US')} bytes): ${value.collection.shellSourceCount} retained Vantage shell sources, ${value.collection.featureMfeSourceCount} directly exposed production feature-MFE chunks, and ${value.collection.nestedFeatureMfeSourceCount} production contact/account consumer chunks derived from their own public runtime maps. All 19 shell sources matched the SHA-256 recorded by the prior BLANCHE feature-map audit; fresh hashes are recorded for the MFE chunks. No form, credential, storage value, DEV/SIT host, or unlisted remote was accessed.`,
    '',
    'A literal `false` or `!1` is not, by itself, a disabled product feature. The inventory includes component defaults, reducer transitions, library options, property descriptors, and runtime bookkeeping. Use the classification and role fields as triage aids, then inspect the occurrence evidence in the JSON.',
    '',
    '## Summary',
    '',
    '| Measure | Count |',
    '| --- | ---: |',
    `| Boolean-like occurrences | ${value.summary.booleanOccurrenceCount} |`,
    `| Unique exact keys | ${value.summary.uniqueKeyCount} |`,
    `| App/business-classified occurrences | ${value.summary.appBusinessOccurrenceCount} |`,
    `| Library/runtime-classified occurrences | ${value.summary.libraryRuntimeOccurrenceCount} |`,
    `| Keys observed as both true and false | ${value.summary.dualValuedKeyCount} |`,
    `| Reducer/state-associated keys | ${value.summary.reducerStateKeyCount} |`,
    `| Environment maps parsed from production files | ${value.summary.environmentMapCount} |`,
    `| Uppercase action/state/status tokens | ${value.summary.stateAndActionTokenCount} |`,
    `| Dynamic boolean-shaped bindings | ${value.summary.dynamicBooleanBindingCount} |`,
    `| Perusal-linked control bindings | ${value.summary.perusalControlBindingCount} |`,
    `| Feature consumer guard expressions | ${value.summary.consumerGuardEvidenceCount} |`,
    `| Reviewed Vantage-owned occurrences | ${value.summary.reviewedVantageOccurrenceCount} |`,
    `| Reviewed Vantage-owned keys | ${value.summary.reviewedVantageKeyCount} |`,
    `| Parser diagnostics | ${value.summary.parserDiagnosticCount} |`,
    '',
    '## Reviewed Vantage-owned fields',
    '',
    'This subset uses explicit reviewed module provenance (shell modules 80288 and 27597, the Terms/User-Profile application modules, and non-library modules in the six nested contact/account chunks). It avoids treating bundled Axios/React metadata as Vantage fields. The JSON still retains every raw occurrence and the broader heuristic classification.',
    '',
    '| Key | Values | Count | Roles | Sources |',
    '| --- | --- | ---: | --- | --- |',
    ...appKeys.slice(0, 100).map(
      (entry) =>
        `| \`${escapeMarkdown(entry.key)}\` | ${entry.observedValues.map((item) => `\`${item}\``).join(', ')} | ${entry.totalCount} | ${entry.roles.map(escapeMarkdown).join(', ')} | ${entry.sourceFilenames.map((item) => `\`${escapeMarkdown(item)}\``).join('<br>')} |`
    ),
    '',
    '## Keys observed with both values',
    '',
    '| Key | True | False | Classification |',
    '| --- | ---: | ---: | --- |',
    ...dual.map(
      (entry) =>
        `| \`${escapeMarkdown(entry.key)}\` | ${entry.valueCounts.true} | ${entry.valueCounts.false} | app ${entry.classificationCounts['app-business']} / library ${entry.classificationCounts['library-runtime']} |`
    ),
    '',
    '## Reducer and state-associated fields',
    '',
    '| Key | Values | Count | Sources |',
    '| --- | --- | ---: | --- |',
    ...reducer.slice(0, 100).map(
      (entry) =>
        `| \`${escapeMarkdown(entry.key)}\` | ${entry.observedValues.map((item) => `\`${item}\``).join(', ')} | ${entry.totalCount} | ${entry.sourceFilenames.map((item) => `\`${escapeMarkdown(item)}\``).join('<br>')} |`
    ),
    '',
    '## Perusal control path',
    '',
    'The Terms-of-Use MFE initializes `isPerusal` to false, accepts the host profile `perusal` value with a false fallback, and binds the resulting state to UI `disabled` properties. These are dynamic mode controls, not a static global feature-off flag.',
    '',
    '| Control key | Referenced state | Control | Test/value | Source offset |',
    '| --- | --- | --- | --- | ---: |',
    ...value.perusalControlBindings.map(
      (entry) =>
        `| \`${escapeMarkdown(entry.key)}\` | \`${escapeMarkdown((entry.referencedKeys ?? []).join(' + ') || entry.referencedKey || entry.valueExpression)}\` | \`${escapeMarkdown(entry.controlType ?? 'unknown')}\` | ${entry.testId ? `test \`${escapeMarkdown(entry.testId)}\`` : entry.controlValue ? `value \`${escapeMarkdown(entry.controlValue)}\`` : ''} | ${entry.sourceOffset} |`
    ),
    '',
    '## Nested contact/account control bindings',
    '',
    '| Feature source | Control key | Referenced state/expression | Control/test ID | Offset |',
    '| --- | --- | --- | --- | ---: |',
    ...value.reviewedVantageOwnedSubset.dynamicBooleanBindings
      .filter((entry) => entry.sourceSet === 'nested-feature-mfe')
      .slice(0, 100)
      .map(
        (entry) =>
          `| ${escapeMarkdown(entry.feature)} | \`${escapeMarkdown(entry.key)}\` | \`${escapeMarkdown((entry.referencedKeys ?? []).join(' + ') || entry.referencedKey || entry.valueExpression)}\` | \`${escapeMarkdown(entry.testId ?? entry.controlType ?? 'unknown')}\` | ${entry.sourceOffset} |`
      ),
    '',
    '### Consumer guards',
    '',
    '| Feature source | Guard type | Referenced keys | Condition | Offset |',
    '| --- | --- | --- | --- | ---: |',
    ...value.consumerGuardEvidence
      .filter((entry) => entry.sourceSet === 'nested-feature-mfe')
      .slice(0, 100)
      .map(
        (entry) =>
          `| ${escapeMarkdown(entry.feature)} | ${entry.guardType} | ${entry.referencedKeys.map((item) => `\`${escapeMarkdown(item)}\``).join(', ')} | \`${escapeMarkdown(entry.condition)}\` | ${entry.sourceOffset} |`
      ),
    '',
    '## Environment maps',
    '',
    'These URLs were parsed as inert literals from production source. `contacted` is false for every mapped target.',
    '',
    '| Mapping key | Variants | Environment labels | Production hostname(s) |',
    '| --- | ---: | --- | --- |',
    ...value.environmentMaps.map((entry) => {
      const labels = [
        ...new Set(entry.variants.flatMap((variant) => Object.keys(variant.environments)))
      ].sort();
      const productionHosts = [
        ...new Set(
          entry.variants.map((variant) => variant.environments.prd?.hostname).filter(Boolean)
        )
      ].sort();
      return `| \`${escapeMarkdown(entry.mappingKey)}\` | ${entry.variantCount} | ${labels.map((item) => `\`${item}\``).join(', ')} | ${productionHosts.map((item) => `\`${escapeMarkdown(item)}\``).join('<br>')} |`;
    }),
    '',
    '## Files',
    '',
    '- `blanche-boolean-inventory.json` — complete machine-readable inventory with counts, values, source/chunk/module offsets, roles, and snippets.',
    '- `run-blanche-boolean-inventory.mjs` — reproducible bounded collector/parser.',
    '',
    '## Caveat',
    '',
    value.method.caveat,
    ''
  ];
  return `${lines.join('\n')}\n`;
}

function escapeMarkdown(value) {
  return String(value).replace(/\|/gu, '\\|').replace(/`/gu, '\\`');
}
