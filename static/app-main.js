import "./meta.js";
import "./i18n.js";
import "./table-pager.js";
import { apiFetch, markTabDirty, notifyError, setTabActivationHandlers } from "./app.js";
import { loadAuth } from "./app-auth-view.js";
import { loadDeliv } from "./app-deliveries.js";
import { loadAudit, loadLogs } from "./app-logs.js";
import { loadCascade, loadDedup, loadDelivery } from "./app-delivery-grouping.js";
import { loadFlow, setupFlowAutorefresh } from "./app-flow.js";
import { loadAcks, loadInhibRules, loadSchedules } from "./app-inhibitions.js";
import { loadRC } from "./app-render-preview.js";
import { loadIngestAuth, loadNtfyTopics, loadRouting } from "./app-routing.js";
import { loadSetup, runPolicySimulation } from "./app-setup-simulator.js";
import { loadConfigBackups, loadStatus, setTabBadge } from "./app-status.js";
import { loadEmergencies } from "./app-emergencies.js";
import { setupSidebar } from "./app-sidebar.js";
import { setupSettingsNavigation } from "./app-settings-nav.js";
import { startApp } from "./app-bootstrap.js";

setTabActivationHandlers({
  flow: () => { loadFlow(); setupFlowAutorefresh(); },
  status: () => loadStatus(),
  auth: () => loadAuth(),
  deliveries: () => loadDeliv(),
  emergencies: () => loadEmergencies(),
  routing: () => { loadRouting(); loadNtfyTopics(); loadIngestAuth(); },
  render: () => loadRC(),
  cascade: () => loadCascade(),
  delivery: () => loadDelivery(),
  grouping: () => loadDedup(),
  inhibitions: () => { loadInhibRules(); loadSchedules(); loadAcks(); },
  logs: () => loadLogs(),
  audit: () => loadAudit({ reset: true }),
  setup: () => { loadSetup(); loadConfigBackups(); },
  simulator: () => runPolicySimulation({ silent: true }),
});

Object.assign(window, {
  _markTabDirty: markTabDirty,
  apiFetch,
  loadStatus,
  notifyError,
  setTabBadge,
});

setupSidebar();
setupSettingsNavigation();
startApp();
