import { IT_AUTH_MESSAGES } from "./i18n-it-auth.js";
import { IT_DASHBOARD_MESSAGES } from "./i18n-it-dashboard.js";
import { buildItalianLegalMessages } from "./i18n-it-legal.js";
import { buildItalianOperationalMessages } from "./i18n-it-operational.js";
import { IT_WORKFLOW_MESSAGES } from "./i18n-it-workflows.js";
import { IT_STATIC_CORE_MESSAGES } from "./i18n-it-static-core.js";
import { IT_STATIC_SETTINGS_MESSAGES } from "./i18n-it-static-settings.js";
export function buildItalianMessages({ authorLink: authorLink }) {
  return {
    ...IT_STATIC_CORE_MESSAGES,
    ...IT_STATIC_SETTINGS_MESSAGES,
    ...buildItalianLegalMessages(authorLink),
    ...buildItalianOperationalMessages(),
    ...IT_DASHBOARD_MESSAGES,
    ...IT_AUTH_MESSAGES,
    ...IT_WORKFLOW_MESSAGES,
  };
}
