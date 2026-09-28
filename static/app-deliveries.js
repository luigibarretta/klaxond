import { loadDeliv, setDeliveryRenderer } from "./app-deliveries-data.js";
import { renderDeliv } from "./app-deliveries-view.js";

export { loadDeliv } from "./app-deliveries-data.js";
export { renderDeliv } from "./app-deliveries-view.js";
export { exportDeliveriesCsv } from "./app-deliveries-csv.js";

setDeliveryRenderer(renderDeliv);
