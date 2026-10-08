import {
  access,
  readFile
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");

const MANIFEST_PATH = path.join(ROOT, "manifest.json");

const REQUIRED_MANIFEST_VERSION = 3;

const FORBIDDEN_PERMISSIONS = new Set([
  "<all_urls>",
  "webRequestBlocking",
  "nativeMessaging",
  "debugger"
]);

const FORBIDDEN_PERMISSION_PATTERNS = [
  "file:///*"
];

const REQUIRED_CONTENT_SCRIPT_FILE = "src/content/content.js";

const REQUIRED_SERVICE_WORKER_FILE =
  "src/background/service-worker.js";

const REQUIRED_POPUP_FILE =
  "public/popup.html";

const REQUIRED_OPTIONS_FILE =
  "public/options.html";

const REQUIRED_ICONS = [
  "public/icons/icon16.png",
  "public/icons/icon32.png",
  "public/icons/icon48.png",
  "public/icons/icon128.png"
];

function log(message) {
  console.log(`[SanitizerPro Validate] ${message}`);
}

function warn(message) {
  console.warn(`[SanitizerPro Validate] WARNING: ${message}`);
}

function fail(message) {
  console.error(`[SanitizerPro Validate] ERROR: ${message}`);
  process.exitCode = 1;
}

async function fileExists(relativePath) {
  try {
    await access(path.join(ROOT, relativePath));
    return true;
  } catch {
    return false;
  }
}

async function loadManifest() {
  if (!(await fileExists("manifest.json"))) {
    fail("manifest.json does not exist.");
    return null;
  }

  let rawManifest;

  try {
    rawManifest = await readFile(MANIFEST_PATH, "utf8");
  } catch (error) {
    fail(`Unable to read manifest.json: ${error.message}`);
    return null;
  }

  try {
    return JSON.parse(rawManifest);
  } catch (error) {
    fail(`manifest.json contains invalid JSON: ${error.message}`);
    return null;
  }
}

function validateBasicManifest(manifest) {
  log("Checking basic manifest configuration...");

  if (manifest.manifest_version !== REQUIRED_MANIFEST_VERSION) {
    fail(
      `manifest_version must be ${REQUIRED_MANIFEST_VERSION}.`
    );
  }

  if (
    typeof manifest.name !== "string" ||
    manifest.name.trim().length === 0
  ) {
    fail("Manifest name is missing.");
  }

  if (
    typeof manifest.version !== "string" ||
    manifest.version.trim().length === 0
  ) {
    fail("Manifest version is missing.");
  }

  if (
    typeof manifest.description !== "string" ||
    manifest.description.trim().length === 0
  ) {
    fail("Manifest description is missing.");
  }

  if (
    manifest.description &&
    manifest.description.length > 132
  ) {
    fail(
      `Manifest description is ${manifest.description.length} characters. Chrome limits it to 132 characters.`
    );
  }

  log("Basic manifest configuration checked.");
}

function validateBackground(manifest) {
  log("Checking background service worker...");

  const background = manifest.background;

  if (!background) {
    fail("background configuration is missing.");
    return;
  }

  if (
    typeof background.service_worker !== "string" ||
    background.service_worker.length === 0
  ) {
    fail("background.service_worker is missing.");
    return;
  }

  if (background.type && background.type !== "module") {
    fail(
      'background.type must be "module" for this project.'
    );
  }

  if (!background.type) {
    warn(
      'background.type is not explicitly set to "module".'
    );
  }

  log("Background configuration checked.");
}

function validateAction(manifest) {
  log("Checking extension action...");

  if (!manifest.action) {
    fail("action configuration is missing.");
    return;
  }

  if (
    typeof manifest.action.default_popup !== "string" ||
    manifest.action.default_popup.length === 0
  ) {
    fail("action.default_popup is missing.");
  }

  log("Action configuration checked.");
}

function validateOptions(manifest) {
  log("Checking options page...");

  if (!manifest.options_ui) {
    fail("options_ui configuration is missing.");
    return;
  }

  if (
    typeof manifest.options_ui.page !== "string" ||
    manifest.options_ui.page.length === 0
  ) {
    fail("options_ui.page is missing.");
  }

  log("Options configuration checked.");
}

function validatePermissions(manifest) {
  log("Checking permissions...");

  const permissions = Array.isArray(manifest.permissions)
    ? manifest.permissions
    : [];

  const hostPermissions = Array.isArray(
    manifest.host_permissions
  )
    ? manifest.host_permissions
    : [];

  const optionalHostPermissions = Array.isArray(
    manifest.optional_host_permissions
  )
    ? manifest.optional_host_permissions
    : [];

  const allPermissions = [
    ...permissions,
    ...hostPermissions,
    ...optionalHostPermissions
  ];

  for (const permission of allPermissions) {
    if (FORBIDDEN_PERMISSIONS.has(permission)) {
      fail(
        `Forbidden permission detected: ${permission}`
      );
    }

    for (const pattern of FORBIDDEN_PERMISSION_PATTERNS) {
      if (permission === pattern) {
        fail(
          `Forbidden permission pattern detected: ${permission}`
        );
      }
    }
  }

  if (hostPermissions.includes("<all_urls>")) {
    fail(
      "host_permissions must not contain <all_urls>."
    );
  }

  if (permissions.includes("webRequestBlocking")) {
    fail(
      "webRequestBlocking must not be used in this extension."
    );
  }

  if (permissions.includes("nativeMessaging")) {
    fail(
      "nativeMessaging is not permitted in the SanitizerPro baseline."
    );
  }

  if (!permissions.includes("storage")) {
    warn(
      'The "storage" permission is not declared.'
    );
  }

  if (hostPermissions.length === 0) {
    fail(
      "No host permissions are configured."
    );
  }

  if (optionalHostPermissions.length > 0) {
    log(
      `Optional host permissions configured: ${optionalHostPermissions.length}`
    );
  }

  log(
    `Required host permissions configured: ${hostPermissions.length}`
  );

  log("Permission configuration checked.");
}

function validateContentScripts(manifest) {
  log("Checking content scripts...");

  if (!Array.isArray(manifest.content_scripts)) {
    fail("content_scripts must be an array.");
    return;
  }

  if (manifest.content_scripts.length === 0) {
    fail(
      "At least one content script is required."
    );
    return;
  }

  let foundMainContentScript = false;

  for (const [index, contentScript] of
    manifest.content_scripts.entries()) {

    if (
      !Array.isArray(contentScript.matches) ||
      contentScript.matches.length === 0
    ) {
      fail(
        `content_scripts[${index}] has no matches.`
      );
    }

    if (
      !Array.isArray(contentScript.js) ||
      contentScript.js.length === 0
    ) {
      fail(
        `content_scripts[${index}] has no JavaScript files.`
      );
    }

    for (const script of contentScript.js ?? []) {
      if (script === REQUIRED_CONTENT_SCRIPT_FILE) {
        foundMainContentScript = true;
      }
    }

    if (
      contentScript.run_at &&
      ![
        "document_start",
        "document_end",
        "document_idle"
      ].includes(contentScript.run_at)
    ) {
      fail(
        `Invalid run_at value in content_scripts[${index}]: ${contentScript.run_at}`
      );
    }
  }

  if (!foundMainContentScript) {
    fail(
      `Main content script ${REQUIRED_CONTENT_SCRIPT_FILE} is not registered.`
    );
  }

  log("Content script configuration checked.");
}

function validateHostPermissionsAgainstContentScripts(
  manifest
) {
  log(
    "Checking host permission and content-script coverage..."
  );

  const hostPermissions = new Set(
    manifest.host_permissions ?? []
  );

  const matches = new Set();

  for (const contentScript of
    manifest.content_scripts ?? []) {
    for (const match of contentScript.matches ?? []) {
      matches.add(match);
    }
  }

  for (const match of matches) {
    if (!hostPermissions.has(match)) {
      warn(
        `Content script match is not explicitly present in host_permissions: ${match}`
      );
    }
  }

  log(
    `Validated ${matches.size} content-script match patterns.`
  );
}

async function validateRequiredFiles(manifest) {
  log("Checking required files...");

  const requiredFiles = new Set([
    REQUIRED_SERVICE_WORKER_FILE,
    REQUIRED_POPUP_FILE,
    REQUIRED_OPTIONS_FILE,
    ...REQUIRED_ICONS
  ]);

  if (manifest.background?.service_worker) {
    requiredFiles.add(
      manifest.background.service_worker
    );
  }

  if (manifest.action?.default_popup) {
    requiredFiles.add(
      manifest.action.default_popup
    );
  }

  if (manifest.options_ui?.page) {
    requiredFiles.add(
      manifest.options_ui.page
    );
  }

  for (const contentScript of
    manifest.content_scripts ?? []) {
    for (const script of contentScript.js ?? []) {
      requiredFiles.add(script);
    }

    for (const css of contentScript.css ?? []) {
      requiredFiles.add(css);
    }
  }

  for (const [size, iconPath] of Object.entries(
    manifest.icons ?? {}
  )) {
    if (typeof iconPath !== "string") {
      fail(
        `Icon ${size} must contain a string path.`
      );
      continue;
    }

    requiredFiles.add(iconPath);
  }

  for (const relativePath of requiredFiles) {
    if (!(await fileExists(relativePath))) {
      fail(
        `Required file is missing: ${relativePath}`
      );
    }
  }

  log(
    `Checked ${requiredFiles.size} required files.`
  );
}

function validateIcons(manifest) {
  log("Checking icon configuration...");

  if (!manifest.icons) {
    fail("Manifest icons are missing.");
    return;
  }

  const requiredSizes = [
    "16",
    "32",
    "48",
    "128"
  ];

  for (const size of requiredSizes) {
    if (!manifest.icons[size]) {
      fail(
        `Required ${size}px icon is missing.`
      );
    }
  }

  log("Icon configuration checked.");
}

function validateCsp(manifest) {
  log(
    "Checking extension Content Security Policy..."
  );

  const csp =
    manifest.content_security_policy?.extension_pages;

  if (!csp) {
    fail(
      "content_security_policy.extension_pages is missing."
    );
    return;
  }

  if (!csp.includes("script-src 'self'")) {
    fail(
      'Extension CSP must contain "script-src \'self\'".'
    );
  }

  if (csp.includes("unsafe-eval")) {
    fail(
      "unsafe-eval is not permitted."
    );
  }

  if (csp.includes("unsafe-inline")) {
    fail(
      "unsafe-inline is not permitted."
    );
  }

  if (
    csp.includes("http://") ||
    csp.includes("https://")
  ) {
    fail(
      "Remote script sources are not permitted in extension CSP."
    );
  }

  log("Content Security Policy checked.");
}

function validateWebAccessibleResources(manifest) {
  log("Checking web accessible resources...");

  if (
    !manifest.web_accessible_resources ||
    manifest.web_accessible_resources.length === 0
  ) {
    log(
      "No web accessible resources configured. This is acceptable."
    );
    return;
  }

  for (const [
    index,
    resource
  ] of manifest.web_accessible_resources.entries()) {

    if (!Array.isArray(resource.resources)) {
      fail(
        `web_accessible_resources[${index}].resources must be an array.`
      );
    }

    if (
      !Array.isArray(resource.matches) ||
      resource.matches.length === 0
    ) {
      fail(
        `web_accessible_resources[${index}].matches must be a non-empty array.`
      );
    }

    for (const item of resource.resources ?? []) {
      if (
        item === "*" ||
        item === "**/*" ||
        item === "public/*"
      ) {
        warn(
          `Broad web accessible resource detected: ${item}`
        );
      }
    }
  }

  log("Web accessible resource configuration checked.");
}

function validateCommands(manifest) {
  log("Checking commands...");

  if (!manifest.commands) {
    log("No keyboard commands configured.");
    return;
  }

  for (const [
    commandName,
    command
  ] of Object.entries(manifest.commands)) {

    if (
      typeof command.description !== "string" ||
      command.description.trim().length === 0
    ) {
      fail(
        `Command "${commandName}" has no description.`
      );
    }

    if (
      command.suggested_key?.default &&
      typeof command.suggested_key.default !== "string"
    ) {
      fail(
        `Command "${commandName}" has an invalid default shortcut.`
      );
    }

    if (
      command.suggested_key?.mac &&
      typeof command.suggested_key.mac !== "string"
    ) {
      fail(
        `Command "${commandName}" has an invalid mac shortcut.`
      );
    }
  }

  log("Command configuration checked.");
}

function validateSecurityDefaults(manifest) {
  log("Checking security defaults...");

  if (
    manifest.externally_connectable
  ) {
    warn(
      "externally_connectable is configured. This should only be enabled when required."
    );
  }

  if (
    manifest.permissions?.includes("tabs")
  ) {
    warn(
      'The "tabs" permission is present. SanitizerPro should avoid it unless a specific feature requires it.'
    );
  }

  if (
    manifest.permissions?.includes("cookies")
  ) {
    fail(
      'The "cookies" permission is not allowed in the SanitizerPro baseline.'
    );
  }

  if (
    manifest.permissions?.includes("history")
  ) {
    fail(
      'The "history" permission is not allowed in the SanitizerPro baseline.'
    );
  }

  if (
    manifest.permissions?.includes("bookmarks")
  ) {
    fail(
      'The "bookmarks" permission is not allowed in the SanitizerPro baseline.'
    );
  }

  log("Security defaults checked.");
}

async function main() {
  log("Starting SanitizerPro extension validation...");
  log(`Project root: ${ROOT}`);

  const manifest = await loadManifest();

  if (!manifest) {
    process.exit(1);
  }

  validateBasicManifest(manifest);
  validateBackground(manifest);
  validateAction(manifest);
  validateOptions(manifest);
  validatePermissions(manifest);
  validateContentScripts(manifest);
  validateHostPermissionsAgainstContentScripts(manifest);
  await validateRequiredFiles(manifest);
  validateIcons(manifest);
  validateCsp(manifest);
  validateWebAccessibleResources(manifest);
  validateCommands(manifest);
  validateSecurityDefaults(manifest);

  if (process.exitCode === 1) {
    console.error(
      "\n[SanitizerPro Validate] Validation FAILED."
    );
    process.exit(1);
  }

  console.log(
    "\n[SanitizerPro Validate] Validation PASSED."
  );
}

main().catch((error) => {
  console.error(
    "[SanitizerPro Validate] Unexpected validation error:",
    error
  );

  process.exit(1);
});
