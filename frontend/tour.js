// Guided presentation mode: drives the real UI step by step with narration.
(() => {
  const $ = (id) => document.getElementById(id);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let idx = 0, last = null, busy = false, active = false;

  async function until(cond, ms = 8000) {
    const t = Date.now();
    while (!cond() && Date.now() - t < ms) await sleep(60);
    await sleep(400);
  }
  // Run a handshake only if the tour hasn't already set up this exact scenario
  async function ensure(preset, mitm = false, auth = false) {
    const key = [preset, mitm, auth].join();
    if (last === key) return;
    $("presetSelect").value = preset; $("mitmToggle").checked = mitm; $("authToggle").checked = auth;
    const crack = $("crackBtn"); crack.disabled = true;
    $("handshakeBtn").click();
    await until(() => !crack.disabled);
    last = key;
  }
  async function send(tamper = "") {
    $("tamperInput").value = tamper;
    const out = $("bobDecrypted"); out.textContent = "…";
    $("sendBtn").click();
    await until(() => out.textContent !== "…");
    $("tamperInput").value = "";
  }
  async function press(btn, out) {
    $(out).textContent = ""; $(btn).click();
    await until(() => $(out).textContent.trim() !== "");
  }

  const scenes = [
    { title: "Two people, one public wire",
      text: "Alice and Bob want a shared secret, but anyone can read what crosses the wire. Diffie–Hellman lets them agree on that secret without ever sending it.",
      spot: [".stage"], run: async () => { window.scrollTo({ top: 0 }); } },
    { title: "Public numbers out, private keys stay home",
      text: "Both sides know the public prime p and generator g. Each picks a private number and sends only g to the power of it, mod p. Watch the two public keys cross.",
      spot: [".params-bar", ".stage"], run: () => ensure("educational_tiny") },
    { title: "The same secret appears on both sides",
      text: "Alice raises Bob's public key to her private number; Bob does the reverse. The math panel shows both land on the same value, and the square-and-multiply trace shows how it's computed quickly.",
      spot: ["#aliceSecret", "#bobSecret", "#mathPanel"], run: () => ensure("educational_tiny") },
    { title: "Encrypting with the shared secret",
      text: "HKDF turns the secret into an AES-256 key. The message crosses the wire as ciphertext and only Bob can decrypt it.",
      spot: ["#aliceAes", "#wireCiphertext", "#bobDecrypted"], run: async () => { await ensure("educational_tiny"); await send(); } },
    { title: "Why tiny primes are weak",
      text: "With p = 23 an attacker just tries every exponent. Alice's private key falls out in a handful of guesses.",
      spot: ["#crackResult"], run: async () => { await ensure("educational_tiny"); await press("crackBtn", "crackResult"); } },
    { title: "Why 2048 bits is safe",
      text: "Same attack on a 2048-bit prime: about 10^616 candidates. Even a trillion guesses a second would take far longer than the age of the universe.",
      spot: ["#crackResult"], run: async () => { await ensure("production_2048"); await press("crackBtn", "crackResult"); } },
    { title: "Mallory sits in the middle",
      text: "With no authentication, Mallory swaps both public keys for her own. Alice and Bob each end up with a secret shared with her, so she reads and rewrites the message.",
      spot: ["#malloryPanel", "#malloryStolen", "#verdict"], run: async () => { await ensure("educational_medium", true); await send("Transfer 5000 PKR to Mallory"); } },
    { title: "Defence: sign the public keys",
      text: "Each side signs its public key with a long-term Ed25519 identity key. Mallory's forged key fails verification, so the exchange is blocked before any secret exists.",
      spot: ["#verdict", "#eventLog"], run: () => ensure("educational_medium", true, true) },
    { title: "Tamper detection",
      text: "Even without Mallory, flipping a single ciphertext bit breaks AES-GCM's authentication tag, so Bob rejects the packet instead of reading garbage.",
      spot: [".lab-item:nth-child(1)"], run: async () => { await ensure("educational_medium"); await press("tamperBtn", "tamperOut"); } },
    { title: "Smarter attacks: baby-step giant-step",
      text: "A cleverer attacker needs about the square root of p steps instead of p, at the cost of memory. That's why prime size has to grow, not just exceed a threshold.",
      spot: [".lab-item:nth-child(2)"], run: async () => { await ensure("educational_medium"); await press("bsgsBtn", "bsgsOut"); } },
    { title: "Forward secrecy",
      text: "Fresh keys for every session mean stealing one key later only exposes that session. Older traffic stays unreadable.",
      spot: [".lab-item:nth-child(3)"], run: async () => { await ensure("educational_medium"); await press("fsBtn", "fsOut"); } },
    { title: "Summary",
      text: "DH agrees on a secret over an open channel. Big primes defeat brute force, signatures defeat Mallory, and authenticated encryption defeats tampering. Questions?",
      spot: [".foot"], run: async () => {} },
  ];

  function spot(sels) {
    document.querySelectorAll(".spot").forEach((e) => e.classList.remove("spot"));
    const els = sels.flatMap((s) => [...document.querySelectorAll(s)]);
    els.forEach((e) => e.classList.add("spot"));
    if (els[0]) els[0].scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "center" });
  }

  async function go(i) {
    if (busy) return;
    idx = Math.max(0, Math.min(scenes.length - 1, i));
    const s = scenes[idx];
    $("tourStep").textContent = `Step ${idx + 1} of ${scenes.length}`;
    $("tourTitle").textContent = s.title; $("tourText").textContent = s.text;
    $("tourNext").textContent = idx === scenes.length - 1 ? "Finish" : "Next";
    $("tourBack").disabled = idx === 0;
    busy = true; $("tourNext").disabled = $("tourBack").disabled = true;
    try { await s.run(); } catch (e) { console.error(e); }
    spot(s.spot);
    busy = false; $("tourNext").disabled = false; $("tourBack").disabled = idx === 0;
  }
  function start() { active = true; last = null; document.body.classList.add("touring"); $("tour").hidden = false; go(0); }
  function stop() { active = false; document.body.classList.remove("touring"); $("tour").hidden = true; spot([]); }

  $("tourBtn").addEventListener("click", start);
  $("tourExit").addEventListener("click", stop);
  $("tourBack").addEventListener("click", () => go(idx - 1));
  $("tourNext").addEventListener("click", () => (idx === scenes.length - 1 ? stop() : go(idx + 1)));
  document.addEventListener("keydown", (e) => {
    if (!active || e.target.matches("input,select")) return;
    if (e.key === "ArrowRight") $("tourNext").click();
    else if (e.key === "ArrowLeft") $("tourBack").click();
    else if (e.key === "Escape") stop();
  });
})();
