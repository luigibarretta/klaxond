import { EN_AUTH_MESSAGES } from "./i18n-en-auth.js";
import { EN_DASHBOARD_MESSAGES } from "./i18n-en-dashboard.js";
import { buildEnglishLegalMessages } from "./i18n-en-legal.js";
import { buildEnglishOperationalMessages } from "./i18n-en-operational.js";
import { EN_WORKFLOW_MESSAGES } from "./i18n-en-workflows.js";
import { EN_STATIC_CORE_MESSAGES } from "./i18n-en-static-core.js";
import { EN_STATIC_SETTINGS_MESSAGES } from "./i18n-en-static-settings.js";
export function buildEnglishMessages({ authorLink: authorLink }) {
  return {
    ...EN_STATIC_CORE_MESSAGES,
    ...EN_STATIC_SETTINGS_MESSAGES,
    ...buildEnglishLegalMessages(authorLink),
    ...buildEnglishOperationalMessages(),
    ...EN_DASHBOARD_MESSAGES,
    ...EN_AUTH_MESSAGES,
    ...EN_WORKFLOW_MESSAGES,
  };
}
