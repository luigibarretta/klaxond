import { IT_OPERATIONAL_CORE_MESSAGES } from "./i18n-it-operational-core.js";
import { IT_OPERATIONAL_DELIVERY_MESSAGES } from "./i18n-it-operational-delivery.js";
export function buildItalianOperationalMessages() {
  return {
    ...IT_OPERATIONAL_CORE_MESSAGES,
    ...IT_OPERATIONAL_DELIVERY_MESSAGES,
  };
}
