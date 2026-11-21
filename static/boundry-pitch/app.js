/* Boundry Pitch Quiz — client */
(function () {
  const STORAGE = "boundry_pitch_v1";
  function loadProgress() {
    try { return JSON.parse(localStorage.getItem(STORAGE) || "{}"); } catch (e) { return {}; }
  }
  function saveProgress(p) { localStorage.setItem(STORAGE, JSON.stringify(p)); }

  const deck = window.BOUNDRY_PITCH_DECK;
  const home = document.getElementById("screen-home");
  const quiz = document.getElementById("screen-quiz");
  const list = document.getElementById("deck-list");
  const card = document.getElementById("quiz-card");
  if (!deck || !deck.decks) {
    list.innerHTML =
      "<p class='stat' style='color:#ff8c00'>Quiz data did not load. On your phone use http://&lt;PC-LAN-IP&gt;:5000/pitch (same Wi-Fi). On the PC run: $env:FLASK_BIND_HOST = \\\"0.0.0.0\\\"; python app.py. Do not open the HTML file from disk.</p>";
    return;
  }

  let currentDeck = null;
  let items = [];
  let idx = 0;
  let prog = loadProgress();
  const progressEl = document.getElementById("progress");

  deck.decks.forEach(function (d) {
    const done = (prog[d.id] && prog[d.id].done) || 0;
    const b = document.createElement("button");
    b.type = "button";
    b.className = "deck";
    b.innerHTML = d.name + "<br><span>" + d.items.length + " cards · best " + done + "/" + d.items.length + "</span>";
    b.onclick = function () { startDeck(d); };
    list.appendChild(b);
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/static/boundry-pitch/sw.js").catch(function () {});
  }
  if (window.matchMedia("(display-mode: standalone)").matches) {
    document.getElementById("install-hint").textContent = "Installed. Works offline after first load.";
  } else {
    document.getElementById("install-hint").textContent =
      "Tip: open once on your PC URL, then Add to Home Screen (iPhone Share menu).";
  }

  document.getElementById("btn-back").onclick = function () {
    quiz.classList.remove("active");
    home.classList.add("active");
  };
  let score = 0;
  const btnNext = document.getElementById("btn-next");

  function onNext() {
    idx++;
    if (idx >= items.length) {
      const pct = Math.round(100 * score / items.length);
      prog[currentDeck.id] = { done: score, total: items.length, pct: pct, at: new Date().toISOString() };
      saveProgress(prog);
      card.innerHTML = "<p>Deck complete. Score " + score + "/" + items.length + " (" + pct + "%).</p>";
      btnNext.textContent = "Finish";
      btnNext.onclick = function () { location.reload(); };
      return;
    }
    renderItem();
  }
  btnNext.onclick = onNext;

  function startDeck(d) {
    currentDeck = d;
    items = d.items.slice().sort(function () { return Math.random() - 0.5; });
    idx = 0;
    score = 0;
    home.classList.remove("active");
    quiz.classList.add("active");
    btnNext.textContent = "Next";
    btnNext.onclick = onNext;
    renderItem();
  }

  function renderItem() {
    const it = items[idx];
    progressEl.textContent = (idx + 1) + " / " + items.length;
    card.innerHTML = "";
    if (it.type === "mcq") {
      const q = document.createElement("div");
      q.className = "q";
      q.textContent = it.q;
      card.appendChild(q);
      let answered = false;
      it.choices.forEach(function (c, i) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "choice";
        b.textContent = c;
        b.onclick = function () {
          if (answered) return;
          answered = true;
          if (i === it.answer_idx) {
            b.classList.add("ok");
            score++;
          } else {
            b.classList.add("bad");
          }
          const ex = document.createElement("div");
          ex.className = "explain";
          ex.textContent = it.explain || "";
          card.appendChild(ex);
        };
        card.appendChild(b);
      });
    } else {
      const t = document.createElement("div");
      t.className = "flash-term";
      t.textContent = it.term || "Term";
      card.appendChild(t);
      const p = document.createElement("div");
      p.className = "flash-prompt";
      p.textContent = it.prompt || "Say it out loud.";
      card.appendChild(p);
      const m = document.createElement("div");
      m.className = "flash-model";
      m.textContent = it.model || "";
      card.appendChild(m);
      const rev = document.createElement("button");
      rev.type = "button";
      rev.className = "btn primary";
      rev.textContent = "Show model answer";
      rev.onclick = function () {
        m.classList.add("show");
        score++;
      };
      card.appendChild(rev);
    }
  }
})();
