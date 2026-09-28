import { EN_OPERATIONAL_CORE_MESSAGES } from "./i18n-en-operational-core.js";
import { EN_OPERATIONAL_DELIVERY_MESSAGES } from "./i18n-en-operational-delivery.js";
export function buildEnglishOperationalMessages() {
  return {
    ...EN_OPERATIONAL_CORE_MESSAGES,
    ...EN_OPERATIONAL_DELIVERY_MESSAGES,
  };
}
