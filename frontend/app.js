const $ = (id) => document.getElementById(id);
const sendBtn = $("sendBtn"), crackBtn = $("crackBtn"), lane = $("lane");
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const sleep = (ms) => new Promise((r) => setTimeout(r, reduce ? 0 : ms));

// Fly a labelled packet along the lane (from/to are fractions 0..1)
async function fly(label, cls, from, to, ms = 900) {
  const el = document.createElement("span");
  el.className = `pkt ${cls}`; el.textContent = label;
  lane.appendChild(el);
  const w = lane.clientWidth - el.offsetWidth;
  const anim = el.animate(
    [{ transform: `translateX(${from * w}px)` }, { transform: `translateX(${to * w}px)` }],
    { duration: reduce ? 1 : ms, easing: "ease-in-out", fill: "forwards" });
  await anim.finished; el.remove();
}
const put = (id, v) => { const e = $(id); e.textContent = v; e.classList.remove("flash"); void e.offsetWidth; e.classList.add("flash"); };

function showVerdict(status) {
  const v = $("verdict");
  const msg = {
    secure: "Secure channel: Alice and Bob derived the same secret, and nobody else knows it.",
    compromised: "Compromised: Mallory shares a different secret with each side and can read everything.",
    blocked: "Attack blocked: the Ed25519 signature check failed, so the forged key was rejected.",
  }[status];
  v.hidden = !msg; v.className = `verdict ${status}`; v.textContent = msg || "";
}

function logEvent(list, text) {
  const li = document.createElement("li"); li.textContent = text;
  if (/ALERT|COMPROMISED|FAILED/.test(text)) li.className = "bad";
  else if (/SUCCESS|verified/.test(text)) li.className = "good";
  else if (/DEFENSE/.test(text)) li.className = "warn";
  list.appendChild(li);
}

function trace(g, a, p) {
  let r = 1n; const out = [];
  for (const bit of a.toString(2)) {
    r = (r * r) % p; let s = `square → ${r}`;
    if (bit === "1") { r = (r * g) % p; s += `, multiply by ${g} → ${r}`; }
    out.push(`bit ${bit}: ${s}`);
  }
  return out.join("<br>");
}

// Worked modular arithmetic, only when the numbers are small enough to show in full
function renderMath(d) {
  const body = $("mathBody");
  const vals = [d.preset.p, d.preset.g, d.alice.private_key, d.bob.private_key, d.alice.public_key,
    d.bob.public_key, d.alice.received_key, d.bob.received_key];
  if (!vals.every((v) => /^\d+$/.test(String(v)))) {
    body.textContent = "These numbers are too large to print in full, but the same two steps (gᵃ mod p, then Bᵃ mod p) run on the 2048-bit values."; return;
  }
  const [p, g, a, b, A, B, rA, rB] = vals.map(BigInt);
  const pw = (x, e, m) => { let r = 1n; x %= m; while (e > 0n) { if (e & 1n) r = (r * x) % m; x = (x * x) % m; e >>= 1n; } return r; };
  const row = (t, expr, res, ref) =>
    `<div class="eq"><small>${t}</small>${expr} = <b>${res}</b> ${res.toString() === String(ref) ? '<span class="ok">✓</span>' : '<span>✗</span>'}</div>`;
  body.innerHTML =
    row("Alice's public key", `${g}<sup>${a}</sup> mod ${p}`, pw(g, a, p), A) +
    row("Bob's public key", `${g}<sup>${b}</sup> mod ${p}`, pw(g, b, p), B) +
    row("Alice's secret", `${rA}<sup>${a}</sup> mod ${p}`, pw(rA, a, p), d.alice.shared_secret) +
    row("Bob's secret", `${rB}<sup>${b}</sup> mod ${p}`, pw(rB, b, p), d.bob.shared_secret) +
    `<div class="eq wide"><small>Square-and-multiply for Alice's public key (${a.toString(2)} in binary): square for every bit, multiply by g when the bit is 1</small>${trace(g, a, p)}</div>`;
}

$("handshakeBtn").addEventListener("click", async () => {
  const mitm = $("mitmToggle").checked;
  const res = await fetch("/api/handshake", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ preset_key: $("presetSelect").value, mitm_enabled: mitm, auth_enabled: $("authToggle").checked }),
  });
  const data = await res.json();

  $("paramP").textContent = data.preset.p; $("paramG").textContent = data.preset.g;
  $("malNode").hidden = !mitm;
  const badge = $("statusBadge"); badge.textContent = data.status.toUpperCase(); badge.className = `badge ${data.status}`;
  showVerdict(data.status);

  const list = $("eventLog"); list.innerHTML = "";
  $("wireCiphertext").textContent = "No packet sent yet."; $("malloryStolen").hidden = true;
  $("bobDecrypted").textContent = "Waiting for a message…"; $("crackResult").textContent = ""; $("crackMeter").hidden = true;
  sendBtn.disabled = true; crackBtn.disabled = true;
  ["alice", "bob"].forEach((n) => ["Priv", "Pub", "Recv", "Secret", "Aes"].forEach((k) => ($(n + k).textContent = "—")));

  // Animated exchange: public keys cross the wire (swapped by Mallory if she is active)
  const flights = [];
  if (mitm) {
    flights.push(fly("A", "a", 0, 0.5), fly("B", "b", 1, 0.5));
    await Promise.all(flights);
    await Promise.all([fly("M", "m", 0.5, 1), fly("M", "m", 0.5, 0)]);
  } else {
    await Promise.all([fly("A", "a", 0, 1), fly("B", "b", 1, 0)]);
  }

  const keys = { Priv: "private_key", Pub: "public_key", Recv: "received_key", Secret: "shared_secret", Aes: "aes_key_hex" };
  for (const who of ["alice", "bob"]) for (const [id, k] of Object.entries(keys)) put(who + id, data[who][k]);

  data.events.forEach((ev) => logEvent(list, ev));
  const mp = $("malloryPanel");
  if (data.mallory) { mp.hidden = false; $("malloryPub").textContent = data.mallory.public_key; $("mallorySecA").textContent = data.mallory.secret_with_alice; $("mallorySecB").textContent = data.mallory.secret_with_bob; }
  else mp.hidden = true;
  renderMath(data);

  sendBtn.disabled = data.status === "blocked"; crackBtn.disabled = false;
});

sendBtn.addEventListener("click", async () => {
  const plaintext = $("plaintextInput").value.trim();
  if (!plaintext) return;
  const res = await fetch("/api/send-message", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plaintext, tamper_text: $("tamperInput").value.trim() || null }),
  });
  const data = await res.json();
  if (!res.ok) { showVerdict("blocked"); $("verdict").textContent = data.detail || "Transmission error."; return; }

  if (data.mallory_log) {
    await fly("🔒 AES-GCM", "c", 0, 0.5); await sleep(250);
    await fly("🔒 forged", "m", 0.5, 1);
  } else await fly("🔒 AES-GCM", "c", 0, 1, 1200);

  put("wireCiphertext", `Nonce: ${data.wire_nonce} | Ciphertext: ${data.wire_ciphertext}`);
  const s = $("malloryStolen");
  if (data.mallory_log) { s.hidden = false; s.textContent = `Mallory read "${data.mallory_log.stolen_plaintext}" and forwarded "${data.mallory_log.forwarded_plaintext}"`; }
  else s.hidden = true;
  $("bobDecrypted").textContent = data.bob_received;
});

crackBtn.addEventListener("click", async () => {
  const data = await (await fetch("/api/crack-demo", { method: "POST" })).json();
  const out = $("crackResult"), meter = $("crackMeter"), fill = $("crackFill");
  meter.hidden = false; fill.style.transition = "none"; fill.style.width = "0";
  void fill.offsetWidth; fill.style.transition = `width ${reduce ? 0 : 1.2}s ease-out`;
  if (data.cracked) {
    fill.style.width = "100%";
    out.textContent = `Cracked in ${data.elapsed_ms} ms after ${data.steps_tried} guesses. Recovered Alice's private key a = ${data.recovered_private_key}. Small primes offer no protection.`;
  } else {
    fill.style.width = "0.4%";
    out.textContent = `${data.reason} A 2048-bit prime means about 10^616 candidates; at a trillion guesses per second that is roughly 10^597 years.`;
  }
});

// ---- Attack and defence lab ----
async function lab(url, body) {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Request failed");
  return data;
}
const labRun = (btn, out, fn) => btn.addEventListener("click", async () => {
  try { out.innerHTML = await fn(); } catch (e) { out.innerHTML = `<span class="bad">${e.message}</span>`; }
});

labRun($("tamperBtn"), $("tamperOut"), async () => {
  const d = await lab("/api/tamper-test", { bit_index: Math.floor(Math.random() * 64) });
  const i = Math.floor(d.flipped_bit / 8) * 2;
  const hex = d.tampered_hex.slice(0, i) + `<span class="flip">${d.tampered_hex.slice(i, i + 2)}</span>` + d.tampered_hex.slice(i + 2);
  return `Bit ${d.flipped_bit} flipped:<br>${hex}<br><span class="${d.detected ? "good" : "bad"}">${d.detected ? "Bob rejected the packet: the authentication tag no longer matches." : "Tamper went unnoticed."}</span>`;
});

labRun($("bsgsBtn"), $("bsgsOut"), async () => {
  const d = await lab("/api/bsgs-demo");
  if (!d.feasible) return `<span class="bad">${d.reason}</span>`;
  const pct = Math.max(2, (d.bsgs.steps / d.brute_steps) * 100).toFixed(1);
  return `Brute force: ${d.brute_steps} steps<br>Baby-step giant-step: ${d.bsgs.steps} steps (${pct}% of that)<br>Recovered a = ${d.bsgs.x}. It needs a table of ${d.bsgs.table_size} entries, which is why 2048 bits stays safe.`;
});

labRun($("fsBtn"), $("fsOut"), async () => {
  const d = await lab("/api/forward-secrecy");
  return d.results.map((r) => r.readable
    ? `<span class="bad">Session ${r.session}: readable → "${r.text}"</span>`
    : `<span class="good">Session ${r.session}: still encrypted</span>`).join("<br>") +
    "<br>Only the session whose key was stolen leaks. Older sessions stay safe because their keys were thrown away.";
});
