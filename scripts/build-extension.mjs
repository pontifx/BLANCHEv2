import { build } from 'esbuild';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const extensionDir = path.join(rootDir, 'chromium-extension');
const modulesDir = path.join(extensionDir, 'src', 'modules');
const staticDir = path.join(extensionDir, 'static');
const distDir = path.join(extensionDir, 'dist');
const rootManifestPath = path.join(extensionDir, 'manifest.json');

const entryPoints = {
  background: path.join(extensionDir, 'src', 'background', 'index.ts'),
  sidepanel: path.join(extensionDir, 'src', 'sidepanel', 'index.ts'),
  devtools: path.join(extensionDir, 'src', 'devtools', 'index.ts'),
  'devtools-panel': path.join(extensionDir, 'src', 'devtools', 'panel.ts'),
  'content/bridgeContent': path.join(extensionDir, 'src', 'content', 'bridgeContent.ts'),
  'content/pageInstrumentor': path.join(extensionDir, 'src', 'content', 'pageInstrumentor.ts')
};

await fs.rm(distDir, { recursive: true, force: true });
await fs.mkdir(distDir, { recursive: true });

await build({
  entryPoints,
  outdir: distDir,
  bundle: true,
  format: 'iife',
  target: ['chrome123'],
  platform: 'browser',
  sourcemap: 'inline',
  logLevel: 'info'
});

await copyDirectory(staticDir, distDir);

const manifestBasePath = path.join(extensionDir, 'manifest.base.json');
const manifestBase = JSON.parse(await fs.readFile(manifestBasePath, 'utf8'));
const moduleDescriptors = await loadModuleDescriptors(modulesDir);
const manifest = mergeManifest(manifestBase, moduleDescriptors);

await fs.writeFile(
  path.join(distDir, 'manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`,
  'utf8'
);

const loadableRootManifest = rewriteManifestForRootLoad(manifest);
await fs.writeFile(rootManifestPath, `${JSON.stringify(loadableRootManifest, null, 2)}\n`, 'utf8');

console.log(
  `Built Chromium extension assets into ${path.relative(rootDir, distDir)} and wrote ${path.relative(rootDir, rootManifestPath)}`
);

async function loadModuleDescriptors(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const descriptors = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }

    const descriptorPath = path.join(directory, entry.name, 'descriptor.json');
    try {
      const descriptor = JSON.parse(await fs.readFile(descriptorPath, 'utf8'));
      descriptors.push(descriptor);
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        continue;
      }

      throw error;
    }
  }

  return descriptors;
}

function mergeManifest(baseManifest, descriptors) {
  const permissions = new Set(baseManifest.permissions ?? []);
  const hostPermissions = new Set(baseManifest.host_permissions ?? []);
  const contentScripts = [...(baseManifest.content_scripts ?? [])];
  const webAccessibleResources = [...(baseManifest.web_accessible_resources ?? [])];

  for (const descriptor of descriptors) {
    for (const permission of descriptor.requiredPermissions ?? []) {
      permissions.add(permission);
    }

    for (const hostPermission of descriptor.requiredHostPermissions ?? []) {
      hostPermissions.add(hostPermission);
    }

    for (const contribution of descriptor.manifestContributions?.contentScripts ?? []) {
      if (!containsByValue(contentScripts, contribution)) {
        contentScripts.push(contribution);
      }
    }

    for (const contribution of descriptor.manifestContributions?.webAccessibleResources ?? []) {
      if (!containsByValue(webAccessibleResources, contribution)) {
        webAccessibleResources.push(contribution);
      }
    }
  }

  return {
    ...baseManifest,
    permissions: [...permissions].sort(),
    host_permissions: [...hostPermissions].sort(),
    content_scripts: contentScripts,
    web_accessible_resources: webAccessibleResources
  };
}

function containsByValue(items, candidate) {
  const serializedCandidate = JSON.stringify(candidate);
  return items.some((item) => JSON.stringify(item) === serializedCandidate);
}

function rewriteManifestForRootLoad(manifest) {
  const prefixPath = (value) => {
    if (typeof value !== 'string' || value.startsWith('dist/')) {
      return value;
    }

    return `dist/${value}`;
  };
  const prefixIconMap = (icons) => {
    if (!icons || typeof icons !== 'object') {
      return icons;
    }

    return Object.fromEntries(Object.entries(icons).map(([size, iconPath]) => [size, prefixPath(iconPath)]));
  };

  return {
    ...manifest,
    icons: prefixIconMap(manifest.icons),
    background: manifest.background
      ? {
          ...manifest.background,
          service_worker: prefixPath(manifest.background.service_worker)
        }
      : undefined,
    side_panel: manifest.side_panel
      ? {
          ...manifest.side_panel,
          default_path: prefixPath(manifest.side_panel.default_path)
        }
      : undefined,
    devtools_page: prefixPath(manifest.devtools_page),
    options_page: prefixPath(manifest.options_page),
    action: manifest.action?.default_popup
      ? {
          ...manifest.action,
          default_icon: prefixIconMap(manifest.action.default_icon),
          default_popup: prefixPath(manifest.action.default_popup)
        }
      : manifest.action
        ? {
            ...manifest.action,
            default_icon: prefixIconMap(manifest.action.default_icon)
          }
        : manifest.action,
    content_scripts: (manifest.content_scripts ?? []).map((entry) => ({
      ...entry,
      js: (entry.js ?? []).map(prefixPath),
      css: (entry.css ?? []).map(prefixPath)
    })),
    web_accessible_resources: (manifest.web_accessible_resources ?? []).map((entry) => ({
      ...entry,
      resources: (entry.resources ?? []).map(prefixPath)
    })),
    sandbox: manifest.sandbox
      ? {
          ...manifest.sandbox,
          pages: (manifest.sandbox.pages ?? []).map(prefixPath)
        }
      : undefined
  };
}

async function copyDirectory(sourceDir, targetDir) {
  const entries = await fs.readdir(sourceDir, { withFileTypes: true });

  for (const entry of entries) {
    const sourcePath = path.join(sourceDir, entry.name);
    const targetPath = path.join(targetDir, entry.name);

    if (entry.isDirectory()) {
      await fs.mkdir(targetPath, { recursive: true });
      await copyDirectory(sourcePath, targetPath);
      continue;
    }

    await fs.copyFile(sourcePath, targetPath);
  }
}
