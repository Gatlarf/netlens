// What kind of thing a device is decides which cards on its page make sense. A phone has no second network card, a camera cannot be probed over SSH,
// a computer hosting virtual machines is not a switch. The cards still appear when the device already has something of that kind (data wins over type).
export const typeOf = (device) => device.type_override || device.device_type || device.type || "unknown";

// A machine somebody logs in to: it can have several network cards or a bond, and it can be probed over SSH or WinRM.
const HOSTS = new Set(["pc", "server", "nas", "vm", "unknown"]);
export const isHost = (device) => HOSTS.has(typeOf(device));

// Network gear that has ports and carries other devices.
const GEAR = new Set(["switch", "router", "ap"]);
export const isGear = (device) => GEAR.has(typeOf(device));

// Virtual machines and containers: they hang below their host in the hierarchy, they are not plugged into it.
export const HOSTED = new Set(["vm", "container", "app"]);
