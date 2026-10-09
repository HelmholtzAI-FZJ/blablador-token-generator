// Shared helpers for the dashboard and admin pages. All scripts live in
// static files so the Content-Security-Policy can forbid inline scripts.

// CSRF: the server renders the token into <meta name="csrf-token">;
// attach it as the X-CSRF-Token header on every state-changing fetch.
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function csrfHeaders(extra = {}) {
    const token = getCsrfToken();
    const headers = {...extra};
    if (token) headers['X-CSRF-Token'] = token;
    return headers;
}

// Elements declare behaviour with data-action="name"; one delegated listener
// dispatches clicks, so the markup needs no inline event handlers.
const actions = {};

function registerActions(map) {
    Object.assign(actions, map);
}

document.addEventListener('click', (event) => {
    const element = event.target.closest('[data-action]');
    if (!element || !actions[element.dataset.action]) return;
    event.preventDefault();
    actions[element.dataset.action](element, event);
});

registerActions({
    logout: async () => {
        await fetch('/logout', {method: 'POST', headers: csrfHeaders()});
        window.location.href = '/';
    },
});
