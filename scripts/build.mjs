import { cp, mkdir, rm, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");

const REQUIRED_FILES = [
  "manifest.json",
  "package.json",
  "public/popup.html",
  "public/options.html",
  "public/icons/icon16.png",
  "public/icons/icon32.png",
  "public/icons/icon48.png",
  "public/icons/icon128.png",
  "src/background/service-worker.js",
  "src/content/content.js"
];

function log(message) {
  console.log(`[SanitizerPro Build] ${message}`);
}

function fail(message) {
  console.error(`[SanitizerPro Build] ERROR: ${message}`);
  process.exit(1);
}

async function assertRequiredFiles() {
  const missing = [];

  for (const relativePath of REQUIRED_FILES) {
    const absolutePath = path.join(ROOT, relativePath);

    if (!existsSync(absolutePath)) {
      missing.push(relativePath);
    }
  }

  if (missing.length > 0) {
    fail(
      `Missing required files:\n${missing
        .map((file) => `  - ${file}`)
        .join("\n")}`
    );
  }
}

async function cleanDist() {
  log("Cleaning dist directory...");

  await rm(DIST, {
    recursive: true,
    force: true
  });

  await mkdir(DIST, {
    recursive: true
  });
}

async function copyDirectory(source, destination) {
  await cp(source, destination, {
    recursive: true,
    force: true
  });
}

async function copyRequiredFiles() {
  log("Copying extension files...");

  await cp(
    path.join(ROOT, "manifest.json"),
    path.join(DIST, "manifest.json")
  );

  await copyDirectory(
    path.join(ROOT, "public"),
    path.join(DIST, "public")
  );

  await copyDirectory(
    path.join(ROOT, "src"),
    path.join(DIST, "src")
  );
}

async function removeDevelopmentFiles() {
  const filesToRemove = [
    path.join(DIST, "src", "**", "*.test.js"),
    path.join(DIST, "src", "**", "*.test.mjs")
  ];

  /*
   * The current build intentionally keeps this step conservative.
   * Test files are excluded only when their exact paths are known.
   */
  const testDirectories = [
    path.join(DIST, "src", "test"),
    path.join(DIST, "test")
  ];

  for (const directory of testDirectories) {
    await rm(directory, {
      recursive: true,
      force: true
    });
  }

  void filesToRemove;
}

async function validateManifest() {
  log("Validating manifest...");

  const manifestPath = path.join(DIST, "manifest.json");

  let manifest;

  try {
    const content = await readFile(manifestPath, "utf8");
    manifest = JSON.parse(content);
  } catch (error) {
    fail(`Unable to parse dist/manifest.json: ${error.message}`);
  }

  if (manifest.manifest_version !== 3) {
    fail("Only Manifest V3 is supported.");
  }

  if (!manifest.name) {
    fail("Manifest is missing the name.");
  }

  if (!manifest.version) {
    fail("Manifest is missing the version.");
  }

  if (!manifest.background?.service_worker) {
    fail("Manifest is missing the background service worker.");
  }

  if (!manifest.action?.default_popup) {
    fail("Manifest is missing the default popup.");
  }

  const serviceWorkerPath = path.join(
    DIST,
    manifest.background.service_worker
  );

  const popupPath = path.join(
    DIST,
    manifest.action.default_popup
  );

  if (!existsSync(serviceWorkerPath)) {
    fail(
      `Manifest references a missing service worker: ${manifest.background.service_worker}`
    );
  }

  if (!existsSync(popupPath)) {
    fail(
      `Manifest references a missing popup: ${manifest.action.default_popup}`
    );
  }

  if (manifest.content_scripts) {
    for (const contentScript of manifest.content_scripts) {
      for (const script of contentScript.js ?? []) {
        const scriptPath = path.join(DIST, script);

        if (!existsSync(scriptPath)) {
          fail(
            `Manifest references a missing content script: ${script}`
          );
        }
      }
    }
  }

  for (const [size, iconPath] of Object.entries(manifest.icons ?? {})) {
    const absoluteIconPath = path.join(DIST, iconPath);

    if (!existsSync(absoluteIconPath)) {
      fail(
        `Manifest references a missing ${size}px icon: ${iconPath}`
      );
    }
  }

  log("Manifest validation passed.");
}

async function writeBuildMetadata() {
  const manifestPath = path.join(DIST, "manifest.json");

  const manifest = JSON.parse(
    await readFile(manifestPath, "utf8")
  );

  const metadata = {
    name: manifest.name,
    version: manifest.version,
    manifestVersion: manifest.manifest_version,
    builtAt: new Date().toISOString()
  };

  await writeFile(
    path.join(DIST, "build-manifest.json"),
    `${JSON.stringify(metadata, null, 2)}\n`,
    "utf8"
  );
}

async function build() {
  const startedAt = Date.now();

  log("Starting production build...");
  log(`Project root: ${ROOT}`);
  log(`Output directory: ${DIST}`);

  await assertRequiredFiles();
  await cleanDist();
  await copyRequiredFiles();
  await removeDevelopmentFiles();
  await validateManifest();
  await writeBuildMetadata();

  const elapsed = Date.now() - startedAt;

  log(`Build completed successfully in ${elapsed} ms.`);
  log(`Extension output: ${DIST}`);
}

build().catch((error) => {
  console.error(error);
  process.exit(1);
});
