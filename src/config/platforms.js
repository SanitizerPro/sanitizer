/**
 * SanitizerPro Platform Registry
 *
 * This file is the central registry for supported AI platforms,
 * AI search engines, coding assistants, and traditional search engines.
 *
 * IMPORTANT:
 * Do not place detection rules or sensitive-data patterns here.
 * Platform identification and sensitive-data detection are separate
 * responsibilities.
 */

export const PLATFORM_CATEGORIES = Object.freeze({
  AI_ASSISTANT: "ai_assistant",
  AI_SEARCH: "ai_search",
  AI_CODING: "ai_coding",
  SEARCH_ENGINE: "search_engine",
  PRODUCTIVITY_AI: "productivity_ai",
  GENERIC_AI: "generic_ai",
  GENERIC_SEARCH: "generic_search"
});

export const PLATFORM_CAPABILITIES = Object.freeze({
  TEXT_INPUT: "text_input",
  CONTENT_EDITABLE: "content_editable",
  PASTE: "paste",
  DROP: "drop",
  FILE_UPLOAD: "file_upload",
  FORM_SUBMIT: "form_submit",
  SEND_BUTTON: "send_button",
  KEYBOARD_SEND: "keyboard_send",
  SEARCH_QUERY: "search_query"
});

function createPlatform({
  id,
  name,
  category,
  domains,
  aliases = [],
  capabilities = [],
  priority = 50,
  enabled = true
}) {
  return Object.freeze({
    id,
    name,
    category,
    domains: Object.freeze([...domains]),
    aliases: Object.freeze([...aliases]),
    capabilities: Object.freeze([...capabilities]),
    priority,
    enabled
  });
}

const COMMON_AI_CAPABILITIES = [
  PLATFORM_CAPABILITIES.TEXT_INPUT,
  PLATFORM_CAPABILITIES.CONTENT_EDITABLE,
  PLATFORM_CAPABILITIES.PASTE,
  PLATFORM_CAPABILITIES.DROP,
  PLATFORM_CAPABILITIES.FILE_UPLOAD,
  PLATFORM_CAPABILITIES.FORM_SUBMIT,
  PLATFORM_CAPABILITIES.SEND_BUTTON,
  PLATFORM_CAPABILITIES.KEYBOARD_SEND
];

const SEARCH_CAPABILITIES = [
  PLATFORM_CAPABILITIES.TEXT_INPUT,
  PLATFORM_CAPABILITIES.CONTENT_EDITABLE,
  PLATFORM_CAPABILITIES.PASTE,
  PLATFORM_CAPABILITIES.DROP,
  PLATFORM_CAPABILITIES.FILE_UPLOAD,
  PLATFORM_CAPABILITIES.FORM_SUBMIT,
  PLATFORM_CAPABILITIES.SEARCH_QUERY,
  PLATFORM_CAPABILITIES.KEYBOARD_SEND
];

const AI_CODING_CAPABILITIES = [
  PLATFORM_CAPABILITIES.TEXT_INPUT,
  PLATFORM_CAPABILITIES.CONTENT_EDITABLE,
  PLATFORM_CAPABILITIES.PASTE,
  PLATFORM_CAPABILITIES.DROP,
  PLATFORM_CAPABILITIES.FILE_UPLOAD,
  PLATFORM_CAPABILITIES.FORM_SUBMIT,
  PLATFORM_CAPABILITIES.SEND_BUTTON,
  PLATFORM_CAPABILITIES.KEYBOARD_SEND
];

export const PLATFORMS = Object.freeze([
  /*
   * ============================================================
   * OpenAI
   * ============================================================
   */

  createPlatform({
    id: "chatgpt",
    name: "ChatGPT",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "chatgpt.com",
      "chat.openai.com"
    ],
    aliases: [
      "openai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 100
  }),

  /*
   * ============================================================
   * Anthropic
   * ============================================================
   */

  createPlatform({
    id: "claude",
    name: "Claude",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "claude.ai"
    ],
    aliases: [
      "anthropic"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 100
  }),

  /*
   * ============================================================
   * Google
   * ============================================================
   */

  createPlatform({
    id: "gemini",
    name: "Gemini",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "gemini.google.com"
    ],
    aliases: [
      "google-gemini"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 100
  }),

  /*
   * ============================================================
   * Microsoft
   * ============================================================
   */

  createPlatform({
    id: "copilot",
    name: "Microsoft Copilot",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "copilot.microsoft.com"
    ],
    aliases: [
      "microsoft-copilot",
      "bing-copilot"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 100
  }),

  /*
   * ============================================================
   * Perplexity
   * ============================================================
   */

  createPlatform({
    id: "perplexity",
    name: "Perplexity",
    category: PLATFORM_CATEGORIES.AI_SEARCH,
    domains: [
      "perplexity.ai",
      "www.perplexity.ai"
    ],
    aliases: [
      "perplexity-ai"
    ],
    capabilities: [
      ...COMMON_AI_CAPABILITIES,
      PLATFORM_CAPABILITIES.SEARCH_QUERY
    ],
    priority: 100
  }),

  /*
   * ============================================================
   * xAI
   * ============================================================
   */

  createPlatform({
    id: "grok",
    name: "Grok",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "grok.com",
      "x.com"
    ],
    aliases: [
      "xai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 95
  }),

  /*
   * ============================================================
   * DeepSeek
   * ============================================================
   */

  createPlatform({
    id: "deepseek",
    name: "DeepSeek",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "chat.deepseek.com",
      "deepseek.com"
    ],
    aliases: [
      "deepseek-ai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 100
  }),

  /*
   * ============================================================
   * Meta AI
   * ============================================================
   */

  createPlatform({
    id: "meta-ai",
    name: "Meta AI",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "meta.ai"
    ],
    aliases: [
      "metaai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 95
  }),

  /*
   * ============================================================
   * Mistral
   * ============================================================
   */

  createPlatform({
    id: "mistral",
    name: "Mistral",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "chat.mistral.ai",
      "mistral.ai"
    ],
    aliases: [
      "le-chat",
      "mistral-ai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 90
  }),

  /*
   * ============================================================
   * Poe
   * ============================================================
   */

  createPlatform({
    id: "poe",
    name: "Poe",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "poe.com"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 90
  }),

  /*
   * ============================================================
   * Character AI
   * ============================================================
   */

  createPlatform({
    id: "character-ai",
    name: "Character.AI",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "character.ai"
    ],
    aliases: [
      "characterai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 85
  }),

  /*
   * ============================================================
   * You.com
   * ============================================================
   */

  createPlatform({
    id: "you",
    name: "You.com",
    category: PLATFORM_CATEGORIES.AI_SEARCH,
    domains: [
      "you.com"
    ],
    capabilities: [
      ...COMMON_AI_CAPABILITIES,
      PLATFORM_CAPABILITIES.SEARCH_QUERY
    ],
    priority: 90
  }),

  /*
   * ============================================================
   * Pi
   * ============================================================
   */

  createPlatform({
    id: "pi",
    name: "Pi",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "pi.ai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 80
  }),

  /*
   * ============================================================
   * Qwen
   * ============================================================
   */

  createPlatform({
    id: "qwen",
    name: "Qwen",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "qwen.ai",
      "chat.qwen.ai"
    ],
    aliases: [
      "qwen-chat"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 85
  }),

  /*
   * ============================================================
   * Kimi
   * ============================================================
   */

  createPlatform({
    id: "kimi",
    name: "Kimi",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "kimi.com",
      "kimi.moonshot.cn"
    ],
    aliases: [
      "moonshot-ai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 85
  }),

  /*
   * ============================================================
   * Hugging Face
   * ============================================================
   */

  createPlatform({
    id: "huggingface",
    name: "Hugging Face",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "huggingface.co"
    ],
    aliases: [
      "hf"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 75
  }),

  /*
   * ============================================================
   * Phind
   * ============================================================
   */

  createPlatform({
    id: "phind",
    name: "Phind",
    category: PLATFORM_CATEGORIES.AI_SEARCH,
    domains: [
      "phind.com",
      "www.phind.com"
    ],
    capabilities: [
      ...COMMON_AI_CAPABILITIES,
      PLATFORM_CAPABILITIES.SEARCH_QUERY
    ],
    priority: 90
  }),

  /*
   * ============================================================
   * Cohere
   * ============================================================
   */

  createPlatform({
    id: "cohere",
    name: "Cohere",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "cohere.com",
      "chat.cohere.com"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 75
  }),

  /*
   * ============================================================
   * Blackbox AI
   * ============================================================
   */

  createPlatform({
    id: "blackbox-ai",
    name: "Blackbox AI",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "blackbox.ai",
      "www.blackbox.ai"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 80
  }),

  /*
   * ============================================================
   * Forefront
   * ============================================================
   */

  createPlatform({
    id: "forefront",
    name: "Forefront AI",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "forefront.ai",
      "www.forefront.ai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 65
  }),

  /*
   * ============================================================
   * Ora
   * ============================================================
   */

  createPlatform({
    id: "ora",
    name: "Ora",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "ora.ai",
      "www.ora.ai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 65
  }),

  /*
   * ============================================================
   * Lepton
   * ============================================================
   */

  createPlatform({
    id: "lepton",
    name: "Lepton AI",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "lepton.ai",
      "www.lepton.ai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 60
  }),

  /*
   * ============================================================
   * Reka
   * ============================================================
   */

  createPlatform({
    id: "reka",
    name: "Reka AI",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "reka.ai",
      "www.reka.ai"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 65
  }),

  /*
   * ============================================================
   * LMArena
   * ============================================================
   */

  createPlatform({
    id: "lmarena",
    name: "LM Arena",
    category: PLATFORM_CATEGORIES.AI_ASSISTANT,
    domains: [
      "arena.ai",
      "www.arena.ai"
    ],
    aliases: [
      "lmarena",
      "chatbot-arena"
    ],
    capabilities: COMMON_AI_CAPABILITIES,
    priority: 75
  }),

  /*
   * ============================================================
   * Replit
   * ============================================================
   */

  createPlatform({
    id: "replit",
    name: "Replit",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "replit.com"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 90
  }),

  /*
   * ============================================================
   * v0
   * ============================================================
   */

  createPlatform({
    id: "v0",
    name: "v0",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "v0.dev"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 90
  }),

  /*
   * ============================================================
   * Lovable
   * ============================================================
   */

  createPlatform({
    id: "lovable",
    name: "Lovable",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "lovable.dev"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 90
  }),

  /*
   * ============================================================
   * Bolt
   * ============================================================
   */

  createPlatform({
    id: "bolt",
    name: "Bolt",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "bolt.new"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 90
  }),

  /*
   * ============================================================
   * StackBlitz
   * ============================================================
   */

  createPlatform({
    id: "stackblitz",
    name: "StackBlitz",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "stackblitz.com"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 80
  }),

  /*
   * ============================================================
   * Windsurf / Codeium
   * ============================================================
   */

  createPlatform({
    id: "windsurf",
    name: "Windsurf",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "windsurf.com",
      "www.windsurf.com",
      "codeium.com"
    ],
    aliases: [
      "codeium"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 85
  }),

  /*
   * ============================================================
   * Sourcegraph
   * ============================================================
   */

  createPlatform({
    id: "sourcegraph",
    name: "Sourcegraph",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "sourcegraph.com"
    ],
    aliases: [
      "cody"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 75
  }),

  /*
   * ============================================================
   * GitHub
   * ============================================================
   */

  createPlatform({
    id: "github",
    name: "GitHub",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "github.com"
    ],
    aliases: [
      "github-copilot",
      "copilot"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 85
  }),

  /*
   * ============================================================
   * GitLab
   * ============================================================
   */

  createPlatform({
    id: "gitlab",
    name: "GitLab",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "gitlab.com"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 75
  }),

  /*
   * ============================================================
   * Tabnine
   * ============================================================
   */

  createPlatform({
    id: "tabnine",
    name: "Tabnine",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "tabnine.com",
      "www.tabnine.com"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 70
  }),

  /*
   * ============================================================
   * Cursor
   * ============================================================
   */

  createPlatform({
    id: "cursor",
    name: "Cursor",
    category: PLATFORM_CATEGORIES.AI_CODING,
    domains: [
      "cursor.com",
      "www.cursor.com"
    ],
    capabilities: AI_CODING_CAPABILITIES,
    priority: 85
  }),

  /*
   * ============================================================
   * Google Search
   * ============================================================
   */

  createPlatform({
    id: "google-search",
    name: "Google Search",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "google.com",
      "www.google.com",
      "google.co.uk",
      "www.google.co.uk",
      "google.ca",
      "www.google.ca",
      "google.com.au",
      "www.google.com.au",
      "google.de",
      "www.google.de",
      "google.fr",
      "www.google.fr",
      "google.nl",
      "www.google.nl",
      "google.ie",
      "www.google.ie",
      "google.co.in",
      "www.google.co.in",
      "google.ae",
      "www.google.ae"
    ],
    aliases: [
      "google",
      "google-ai-mode",
      "google-ai-overview"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 100
  }),

  /*
   * ============================================================
   * Bing
   * ============================================================
   */

  createPlatform({
    id: "bing",
    name: "Bing",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "bing.com",
      "www.bing.com"
    ],
    aliases: [
      "bing-copilot"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 100
  }),

  /*
   * ============================================================
   * DuckDuckGo
   * ============================================================
   */

  createPlatform({
    id: "duckduckgo",
    name: "DuckDuckGo",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "duckduckgo.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 90
  }),

  /*
   * ============================================================
   * Yahoo
   * ============================================================
   */

  createPlatform({
    id: "yahoo",
    name: "Yahoo Search",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "search.yahoo.com",
      "search.yahoo.co.uk"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 85
  }),

  /*
   * ============================================================
   * Brave Search
   * ============================================================
   */

  createPlatform({
    id: "brave-search",
    name: "Brave Search",
    category: PLATFORM_CATEGORIES.AI_SEARCH,
    domains: [
      "search.brave.com"
    ],
    aliases: [
      "brave"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 90
  }),

  /*
   * ============================================================
   * Startpage
   * ============================================================
   */

  createPlatform({
    id: "startpage",
    name: "Startpage",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "startpage.com",
      "www.startpage.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 80
  }),

  /*
   * ============================================================
   * Ecosia
   * ============================================================
   */

  createPlatform({
    id: "ecosia",
    name: "Ecosia",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "ecosia.org",
      "www.ecosia.org"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 75
  }),

  /*
   * ============================================================
   * Qwant
   * ============================================================
   */

  createPlatform({
    id: "qwant",
    name: "Qwant",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "qwant.com",
      "www.qwant.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 75
  }),

  /*
   * ============================================================
   * Kagi
   * ============================================================
   */

  createPlatform({
    id: "kagi",
    name: "Kagi",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "kagi.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 75
  }),

  /*
   * ============================================================
   * Yandex
   * ============================================================
   */

  createPlatform({
    id: "yandex",
    name: "Yandex",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "yandex.com",
      "www.yandex.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 70
  }),

  /*
   * ============================================================
   * Baidu
   * ============================================================
   */

  createPlatform({
    id: "baidu",
    name: "Baidu",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "baidu.com",
      "www.baidu.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 70
  }),

  /*
   * ============================================================
   * Naver
   * ============================================================
   */

  createPlatform({
    id: "naver",
    name: "Naver",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "naver.com",
      "www.naver.com",
      "search.naver.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 70
  }),

  /*
   * ============================================================
   * Seznam
   * ============================================================
   */

  createPlatform({
    id: "seznam",
    name: "Seznam",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "seznam.cz",
      "www.seznam.cz"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 60
  }),

  /*
   * ============================================================
   * AOL
   * ============================================================
   */

  createPlatform({
    id: "aol-search",
    name: "AOL Search",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "search.aol.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 55
  }),

  /*
   * ============================================================
   * Ask
   * ============================================================
   */

  createPlatform({
    id: "ask",
    name: "Ask",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "ask.com",
      "www.ask.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 55
  }),

  /*
   * ============================================================
   * Lycos
   * ============================================================
   */

  createPlatform({
    id: "lycos",
    name: "Lycos",
    category: PLATFORM_CATEGORIES.SEARCH_ENGINE,
    domains: [
      "search.lycos.com"
    ],
    capabilities: SEARCH_CAPABILITIES,
    priority: 50
  })
]);

/**
 * Immutable lookup maps.
 */

const PLATFORM_BY_ID = new Map();

const PLATFORM_BY_DOMAIN = new Map();

for (const platform of PLATFORMS) {
  PLATFORM_BY_ID.set(platform.id, platform);

  for (const domain of platform.domains) {
    PLATFORM_BY_DOMAIN.set(
      domain.toLowerCase(),
      platform
    );
  }
}

/**
 * Return all enabled platforms.
 */
export function getEnabledPlatforms() {
  return PLATFORMS.filter(
    (platform) => platform.enabled
  );
}

/**
 * Find a platform by its ID.
 */
export function getPlatformById(id) {
  if (typeof id !== "string") {
    return null;
  }

  return PLATFORM_BY_ID.get(id) ?? null;
}

/**
 * Normalize a hostname.
 */
function normalizeHostname(hostname) {
  if (typeof hostname !== "string") {
    return "";
  }

  return hostname
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

/**
 * Determine whether a hostname belongs to a registered domain.
 *
 * Example:
 *
 * chatgpt.com
 * subdomain.chatgpt.com
 *
 * Both are matched to ChatGPT.
 */
function domainMatchesHostname(
  hostname,
  registeredDomain
) {
  if (
    hostname === registeredDomain
  ) {
    return true;
  }

  return hostname.endsWith(
    `.${registeredDomain}`
  );
}

/**
 * Find a platform from a hostname.
 *
 * The longest matching domain wins.
 * This prevents broad domains from incorrectly
 * overriding more specific domains.
 */
export function getPlatformByHostname(hostname) {
  const normalizedHostname =
    normalizeHostname(hostname);

  if (!normalizedHostname) {
    return null;
  }

  const exactMatch =
    PLATFORM_BY_DOMAIN.get(
      normalizedHostname
    );

  if (exactMatch) {
    return exactMatch;
  }

  let bestMatch = null;
  let bestDomainLength = -1;

  for (const platform of PLATFORMS) {
    if (!platform.enabled) {
      continue;
    }

    for (const domain of platform.domains) {
      const normalizedDomain =
        normalizeHostname(domain);

      if (
        domainMatchesHostname(
          normalizedHostname,
          normalizedDomain
        )
      ) {
        if (
          normalizedDomain.length >
          bestDomainLength
        ) {
          bestMatch = platform;
          bestDomainLength =
            normalizedDomain.length;
        }
      }
    }
  }

  return bestMatch;
}

/**
 * Safely parse a URL and identify its platform.
 */
export function getPlatformByUrl(url) {
  if (typeof url !== "string") {
    return null;
  }

  try {
    const parsedUrl = new URL(url);

    return getPlatformByHostname(
      parsedUrl.hostname
    );
  } catch {
    return null;
  }
}

/**
 * Find platforms by category.
 */
export function getPlatformsByCategory(
  category
) {
  return PLATFORMS.filter(
    (platform) =>
      platform.enabled &&
      platform.category === category
  );
}

/**
 * Determine whether a URL belongs to a
 * registered SanitizerPro platform.
 */
export function isSupportedUrl(url) {
  return Boolean(
    getPlatformByUrl(url)
  );
}

/**
 * Determine whether a platform is an
 * AI destination.
 */
export function isAIPlatform(platform) {
  if (!platform) {
    return false;
  }

  return [
    PLATFORM_CATEGORIES.AI_ASSISTANT,
    PLATFORM_CATEGORIES.AI_SEARCH,
    PLATFORM_CATEGORIES.AI_CODING,
    PLATFORM_CATEGORIES.PRODUCTIVITY_AI,
    PLATFORM_CATEGORIES.GENERIC_AI
  ].includes(platform.category);
}

/**
 * Determine whether a platform is a
 * search destination.
 */
export function isSearchPlatform(platform) {
  if (!platform) {
    return false;
  }

  return [
    PLATFORM_CATEGORIES.AI_SEARCH,
    PLATFORM_CATEGORIES.SEARCH_ENGINE,
    PLATFORM_CATEGORIES.GENERIC_SEARCH
  ].includes(platform.category);
}

/**
 * Determine whether a platform supports
 * file/upload protection.
 */
export function supportsFileUpload(
  platform
) {
  if (!platform) {
    return false;
  }

  return platform.capabilities.includes(
    PLATFORM_CAPABILITIES.FILE_UPLOAD
  );
}

/**
 * Determine whether a platform supports
 * contenteditable monitoring.
 */
export function supportsContentEditable(
  platform
) {
  if (!platform) {
    return false;
  }

  return platform.capabilities.includes(
    PLATFORM_CAPABILITIES.CONTENT_EDITABLE
  );
}

/**
 * Determine whether a platform supports
 * paste protection.
 */
export function supportsPasteProtection(
  platform
) {
  if (!platform) {
    return false;
  }

  return platform.capabilities.includes(
    PLATFORM_CAPABILITIES.PASTE
  );
}

/**
 * Determine whether a platform supports
 * drag-and-drop protection.
 */
export function supportsDropProtection(
  platform
) {
  if (!platform) {
    return false;
  }

  return platform.capabilities.includes(
    PLATFORM_CAPABILITIES.DROP
  );
}

/**
 * Return a safe diagnostic representation.
 *
 * This function intentionally does not accept or
 * return page content, prompts, clipboard data,
 * files, secrets, or PII.
 */
export function getPlatformSummary(
  platform
) {
  if (!platform) {
    return null;
  }

  return {
    id: platform.id,
    name: platform.name,
    category: platform.category,
    priority: platform.priority,
    capabilities: [
      ...platform.capabilities
    ]
  };
}

/**
 * Generic fallback platform.
 *
 * This is intentionally not included in PLATFORMS
 * because it should only be selected by the runtime
 * when no known platform matches.
 */
export const GENERIC_PLATFORMS = Object.freeze({
  AI: Object.freeze({
    id: "generic-ai",
    name: "Unknown AI Platform",
    category: PLATFORM_CATEGORIES.GENERIC_AI,
    domains: Object.freeze([]),
    aliases: Object.freeze([]),
    capabilities: Object.freeze(
      COMMON_AI_CAPABILITIES
    ),
    priority: 1,
    enabled: true
  }),

  SEARCH: Object.freeze({
    id: "generic-search",
    name: "Unknown Search Engine",
    category: PLATFORM_CATEGORIES.GENERIC_SEARCH,
    domains: Object.freeze([]),
    aliases: Object.freeze([]),
    capabilities: Object.freeze(
      SEARCH_CAPABILITIES
    ),
    priority: 1,
    enabled: true
  })
});

/**
 * Return registry statistics without exposing
 * page content or user data.
 */
export function getPlatformRegistryStats() {
  const categories = {};

  for (const platform of PLATFORMS) {
    categories[platform.category] =
      (categories[platform.category] ?? 0) + 1;
  }

  return Object.freeze({
    total: PLATFORMS.length,
    enabled: getEnabledPlatforms().length,
    domains: PLATFORM_BY_DOMAIN.size,
    categories: Object.freeze({
      ...categories
    })
  });
}
