import "./meta.js";
import "./i18n.js";
import "./table-pager.js";
import { apiFetch, markTabDirty, notifyError, setTabActivationHandlers } from "./app.js";
import { loadAuth } from "./app-auth-view.js";
import { loadAudit, loadDeliv, loadLogs } from "./app-deliveries-logs.js";
import { loadCascade, loadDedup, loadDelivery } from "./app-delivery-grouping.js";
import { loadFlow, setupFlowAutorefresh } from "./app-flow.js";
import { loadAcks, loadInhibRules, loadSchedules } from "./app-inhibitions.js";
import { loadRC } from "./app-render-preview.js";
import { loadIngestAuth, loadNtfyTopics } from "./app-routing.js";
import { loadSetup, runPolicySimulation } from "./app-setup-simulator.js";
import { loadStatus, setTabBadge } from "./app-status.js";
import { loadEmergencies } from "./app-emergencies.js";
import { startApp } from "./app-bootstrap.js";

setTabActivationHandlers({
  flow: () => { loadFlow(); setupFlowAutorefresh(); },
  status: () => loadStatus(),
  auth: () => loadAuth(),
  deliveries: () => loadDeliv(),
  emergencies: () => loadEmergencies(),
  routing: () => { loadNtfyTopics(); loadIngestAuth(); },
  render: () => loadRC(),
  cascade: () => loadCascade(),
  delivery: () => loadDelivery(),
  grouping: () => loadDedup(),
  inhibitions: () => { loadInhibRules(); loadSchedules(); loadAcks(); },
  logs: () => loadLogs(),
  audit: () => loadAudit({ reset: true }),
  setup: () => loadSetup(),
  simulator: () => runPolicySimulation({ silent: true }),
});

Object.assign(window, {
  _markTabDirty: markTabDirty,
  apiFetch,
  loadStatus,
  notifyError,
  setTabBadge,
});

startApp();
