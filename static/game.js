/**
 * game.js — Boundry.AI RPG UI Engine
 * Handles XP toasts, level-up modals, achievement unlocks, and XP bar updates.
 * Included on all analyst pages (control_room, cissp_hub, cissp_domain, etc.)
 */

// ─── Toast Queue ───────────────────────────────────────────────────────────

const _toastQueue = [];
let   _toastActive = false;

function _nextToast() {
    if (_toastQueue.length === 0) { _toastActive = false; return; }
    _toastActive = true;
    const { message, type, duration } = _toastQueue.shift();
    const container = _getOrCreateToastContainer();
    const toast = document.createElement("div");
    toast.className = `game-toast game-toast-${type}`;
    toast.innerHTML = message;
    container.appendChild(toast);
    // Animate in
    requestAnimationFrame(() => {
        requestAnimationFrame(() => { toast.classList.add("game-toast-show"); });
    });
    setTimeout(() => {
        toast.classList.remove("game-toast-show");
        toast.classList.add("game-toast-hide");
        setTimeout(() => {
            toast.remove();
            _nextToast();
        }, 400);
    }, duration || 3000);
}

function _getOrCreateToastContainer() {
    let c = document.getElementById("game-toast-container");
    if (!c) {
        c = document.createElement("div");
        c.id = "game-toast-container";
        document.body.appendChild(c);
    }
    return c;
}

/**
 * Show a toast notification.
 * @param {string} message  HTML content
 * @param {string} type     "xp" | "level" | "badge" | "info" | "error"
 * @param {number} duration ms to show (default 3000)
 */
function showToast(message, type = "xp", duration = 3000) {
    _toastQueue.push({ message, type, duration });
    if (!_toastActive) _nextToast();
}


// ─── XP Result Handler ─────────────────────────────────────────────────────

/**
 * Process an XP result object returned from the server and show the appropriate UI.
 * Expected shape:
 * { xp_gained, new_total, old_level, new_level, level_name, level_icon,
 *   level_up, new_achievements: [{badge_id, name, icon, desc}], streak }
 */
function handleXpResult(xp) {
    if (!xp) return;

    // XP gain toast
    const sign = xp.xp_gained >= 0 ? "+" : "";
    showToast(
        `<span class="toast-xp-icon">⚡</span> ${sign}${xp.xp_gained} XP`,
        "xp",
        2500,
    );

    // Update topbar XP bar (if present)
    updateXpBar(xp);

    // Achievement unlocks (queue each one with a short delay)
    if (xp.new_achievements && xp.new_achievements.length > 0) {
        xp.new_achievements.forEach((badge, i) => {
            setTimeout(() => {
                showToast(
                    `<span class="toast-badge-icon">${badge.icon}</span> ` +
                    `<strong>Achievement Unlocked!</strong><br>${badge.name} — ${badge.desc}`,
                    "badge",
                    5000,
                );
            }, i * 400 + 600);
        });
    }

    // Level-up modal
    if (xp.level_up) {
        setTimeout(() => showLevelUpModal(xp), 800);
    }
}


// ─── XP Bar Update ─────────────────────────────────────────────────────────

function updateXpBar(xp) {
    const bar   = document.getElementById("xp-bar-fill");
    const label = document.getElementById("xp-bar-label");
    const lvl   = document.getElementById("xp-level-badge");
    const name  = document.getElementById("xp-level-name");
    if (!bar && !label) return;

    // Fetch fresh state from server to get accurate pct
    fetch("/player/xp")
        .then(r => r.json())
        .then(data => {
            if (bar)   bar.style.width = data.level_pct + "%";
            if (label) label.textContent = `${data.xp.toLocaleString()} XP · ${data.xp_to_next} to next level`;
            if (lvl)   lvl.textContent  = `${data.level_icon} Lv.${data.level}`;
            if (name)  name.textContent = data.level_name;
        })
        .catch(() => {});
}


// ─── Level-Up Modal ────────────────────────────────────────────────────────

function showLevelUpModal(xp) {
    // Remove any existing modal
    const existing = document.getElementById("levelup-modal");
    if (existing) existing.remove();

    const modal = document.createElement("div");
    modal.id = "levelup-modal";
    modal.innerHTML = `
        <div class="levelup-backdrop"></div>
        <div class="levelup-card">
            <div class="levelup-burst">✨</div>
            <div class="levelup-title">LEVEL UP!</div>
            <div class="levelup-icon">${xp.level_icon}</div>
            <div class="levelup-level">Level ${xp.new_level}</div>
            <div class="levelup-name">${xp.level_name}</div>
            <div class="levelup-sub">${xp.new_total.toLocaleString()} XP total</div>
            <button class="levelup-close" onclick="closeLevelUpModal()">Continue &rarr;</button>
        </div>
    `;
    document.body.appendChild(modal);

    // Animate in
    requestAnimationFrame(() => {
        requestAnimationFrame(() => { modal.classList.add("levelup-show"); });
    });

    // Auto-close after 6 seconds
    setTimeout(closeLevelUpModal, 6000);
}

function closeLevelUpModal() {
    const modal = document.getElementById("levelup-modal");
    if (!modal) return;
    modal.classList.add("levelup-hide");
    setTimeout(() => modal.remove(), 500);
}


// ─── Streak Toast ──────────────────────────────────────────────────────────

function showStreakToast(days) {
    if (!days || days < 2) return;
    const fire = days >= 7 ? "🔥🔥🔥" : days >= 3 ? "🔥🔥" : "🔥";
    showToast(
        `${fire} <strong>${days}-day streak!</strong> Keep it going!`,
        "badge",
        4000,
    );
}


// ─── CSS Injection ─────────────────────────────────────────────────────────

(function injectGameStyles() {
    if (document.getElementById("game-styles")) return;
    const style = document.createElement("style");
    style.id = "game-styles";
    style.textContent = `
/* ── Toast ─────────────────────────────────────────────── */
#game-toast-container {
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 9999;
    display: flex;
    flex-direction: column-reverse;
    gap: 10px;
    pointer-events: none;
}
.game-toast {
    padding: 10px 18px;
    border-radius: 8px;
    font-family: 'Segoe UI', sans-serif;
    font-size: 14px;
    font-weight: 600;
    color: #fff;
    background: #1a2a1a;
    border-left: 4px solid #00b432;
    box-shadow: 0 4px 20px rgba(0,0,0,0.6);
    opacity: 0;
    transform: translateX(40px);
    transition: opacity 0.3s ease, transform 0.3s ease;
    line-height: 1.4;
    pointer-events: auto;
    max-width: 300px;
}
.game-toast.game-toast-show {
    opacity: 1;
    transform: translateX(0);
}
.game-toast.game-toast-hide {
    opacity: 0;
    transform: translateX(40px);
}
.game-toast.game-toast-xp   { border-left-color: #00b432; }
.game-toast.game-toast-level { border-left-color: #ffd700; }
.game-toast.game-toast-badge { border-left-color: #9944ee; }
.game-toast.game-toast-info  { border-left-color: #4488ff; }
.game-toast.game-toast-error { border-left-color: #ff4444; }
.toast-xp-icon   { font-size: 16px; margin-right: 6px; }
.toast-badge-icon{ font-size: 20px; margin-right: 8px; }

/* ── XP Bar (topbar) ────────────────────────────────────── */
.xp-bar-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: #aaa;
}
.xp-level-badge {
    background: #1a2a1a;
    border: 1px solid #00b432;
    border-radius: 4px;
    padding: 2px 8px;
    font-weight: 700;
    color: #00b432;
    font-size: 12px;
    white-space: nowrap;
    cursor: pointer;
    text-decoration: none;
}
.xp-level-badge:hover { background: #002200; }
.xp-bar-track {
    width: 120px;
    height: 8px;
    background: #1a1a1a;
    border-radius: 4px;
    overflow: hidden;
    border: 1px solid #333;
}
.xp-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #00b432, #44ff66);
    border-radius: 4px;
    transition: width 0.6s ease;
}
.xp-bar-label {
    font-size: 11px;
    color: #666;
    white-space: nowrap;
}
.xp-streak-badge {
    font-size: 12px;
    color: #ff8c00;
    font-weight: 700;
}

/* ── Level-Up Modal ─────────────────────────────────────── */
#levelup-modal {
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    transition: opacity 0.4s ease;
}
#levelup-modal.levelup-show { opacity: 1; }
#levelup-modal.levelup-hide { opacity: 0; }
.levelup-backdrop {
    position: absolute;
    inset: 0;
    background: rgba(0,0,0,0.85);
    backdrop-filter: blur(4px);
}
.levelup-card {
    position: relative;
    background: linear-gradient(135deg, #0d1a0d 0%, #1a1a2e 100%);
    border: 2px solid #ffd700;
    border-radius: 16px;
    padding: 48px 64px;
    text-align: center;
    box-shadow: 0 0 60px rgba(255,215,0,0.3), 0 20px 80px rgba(0,0,0,0.8);
    transform: scale(0.8);
    transition: transform 0.4s cubic-bezier(0.34,1.56,0.64,1);
    min-width: 320px;
}
#levelup-modal.levelup-show .levelup-card { transform: scale(1); }
#levelup-modal.levelup-hide .levelup-card { transform: scale(0.8); }
.levelup-burst {
    font-size: 40px;
    animation: burst 0.6s ease-out;
    display: block;
    margin-bottom: 8px;
}
@keyframes burst {
    0%   { transform: scale(0) rotate(-20deg); opacity: 0; }
    60%  { transform: scale(1.3) rotate(5deg);  opacity: 1; }
    100% { transform: scale(1) rotate(0deg);    opacity: 1; }
}
.levelup-title {
    font-size: 13px;
    letter-spacing: 6px;
    color: #ffd700;
    font-weight: 800;
    text-transform: uppercase;
    margin-bottom: 12px;
    font-family: 'Courier New', monospace;
}
.levelup-icon  { font-size: 64px; line-height: 1; margin: 8px 0; animation: spinIn 0.5s ease-out; }
@keyframes spinIn {
    from { transform: rotate(-180deg) scale(0); }
    to   { transform: rotate(0) scale(1); }
}
.levelup-level {
    font-size: 48px;
    font-weight: 900;
    color: #ffd700;
    font-family: 'Courier New', monospace;
    text-shadow: 0 0 20px rgba(255,215,0,0.6);
    line-height: 1;
    margin: 8px 0;
}
.levelup-name {
    font-size: 20px;
    font-weight: 700;
    color: #fff;
    margin: 8px 0 4px;
}
.levelup-sub {
    font-size: 13px;
    color: #888;
    margin-bottom: 24px;
}
.levelup-close {
    background: #ffd700;
    color: #000;
    border: none;
    border-radius: 8px;
    padding: 10px 32px;
    font-size: 14px;
    font-weight: 800;
    cursor: pointer;
    letter-spacing: 1px;
    transition: background 0.2s;
}
.levelup-close:hover { background: #ffe44d; }
`;
    document.head.appendChild(style);
})();
