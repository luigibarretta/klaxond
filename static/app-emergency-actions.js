import { apiFetch, confirmDialog, notifyError, notifySuccess, tr } from "./app.js";

export async function acknowledgeEmergencyReceipt(receiptId, context = "emergency-ack") {
  if (!receiptId) return false;
  const confirmed = await confirmDialog(tr("emergency.ack_confirm"), {
    title: tr("emergency.ack"),
    confirmLabel: tr("emergency.ack"),
  });
  if (!confirmed) return false;
  try {
    const response = await apiFetch(`/api/emergencies/${encodeURIComponent(receiptId)}/ack`, {
      method: "POST",
      body: "{}",
      headers: { "Content-Type": "application/json" },
    });
    if (!response.ok) throw new Error(await response.text());
    notifySuccess(tr("emergency.ack_ok"));
    return true;
  } catch (error) {
    notifyError(context, error);
    return false;
  }
}
