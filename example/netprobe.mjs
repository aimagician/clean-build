// Deliberately tries to reach the internet so the egress capture and the
// per-process net report have something to attribute. Run it offline:
//
//     ./clean-builder build example netprobe
//
// It probes TWO escape routes so a pass proves more than "DNS is blocked":
//   1. by hostname  → exercises the DNS path (name resolution must fail)
//   2. by raw IP    → skips DNS entirely, exercising raw TCP egress to an IP
// Both must be blocked. The probe exits non-zero if EITHER reaches the network.
//
// Verdict rule (deliberately simple and robust): a request "reached the
// network" only if it comes back with an HTTP response. ANY thrown error means
// no request completed — the packet was blocked at the ACL, or name resolution
// failed, or the connection was refused/timed out. We do not try to classify
// error codes (that is fragile and can misread a blocked build as a breach).

const TARGETS = [
  { name: "DNS path (hostname)", url: "https://registry.npmjs.org/" },
  { name: "raw-IP path (no DNS)", url: "https://1.1.1.1/" },
];

let breached = false;
for (const t of TARGETS) {
  try {
    const r = await fetch(t.url, { signal: AbortSignal.timeout(8000) });
    console.log(`netprobe: ${t.name} REACHED (HTTP ${r.status}) — the builder is NOT offline`);
    breached = true;
  } catch (e) {
    const why = e.cause?.code ?? e.code ?? e.cause?.name ?? e.name ?? "error";
    console.log(`netprobe: ${t.name} blocked (${why})`);
  }
}

if (breached) process.exit(1);
console.log("netprobe: both paths blocked — the offline contract held");
