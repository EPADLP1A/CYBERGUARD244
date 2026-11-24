// ══════════════════════════════════════════════════
//  CyberGuard AI — JavaScript principal
// ══════════════════════════════════════════════════

// ── Utilitários ──────────────────────────────────

function getRiskLabel(level) {
    return { low: 'Baixo Risco', medium: 'Requer Atenção', high: 'Risco Elevado' }[level] || level;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}

function showLoading(btn) {
    btn.disabled = true;
    btn._origHtml = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> A analisar...';
}

function hideLoading(btn, html) {
    btn.disabled = false;
    btn.innerHTML = html || btn._origHtml || 'Analisar';
}

function showError(msg) {
    const el = document.getElementById('error-msg');
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
}

function clearError() {
    const el = document.getElementById('error-msg');
    if (el) el.style.display = 'none';
}

// ── Validação de URL (client-side) ────────────────
// Espelha services/url_analyzer.py::validate_url — o servidor volta sempre
// a validar, isto serve apenas para dar feedback imediato ao utilizador.

const URL_MAX_LENGTH = 2000;

function validateUrlInput(url) {
    if (!url) return 'Por favor, insere um URL para analisar.';
    if (url.length > URL_MAX_LENGTH) return `URL demasiado longo (máximo ${URL_MAX_LENGTH} caracteres).`;
    if (/\s/.test(url)) return 'O URL não pode conter espaços.';

    const scheme = url.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
    if (scheme && !['http', 'https'].includes(scheme[1].toLowerCase()) && !/^[^/]+:\d+/.test(url)) {
        return 'Apenas são suportados URLs http:// ou https://';
    }

    let parsed;
    try {
        parsed = new URL(/^https?:\/\//i.test(url) ? url : 'http://' + url);
    } catch {
        return 'Formato de URL inválido.';
    }
    const host = parsed.hostname;
    if (!host) return 'O URL não tem um domínio válido.';
    if (host !== 'localhost' && !host.includes('.')) return 'O domínio do URL não é válido (ex.: exemplo.com).';
    return null; // válido
}

function setUrlInputInvalid(input, invalid) {
    if (!input) return;
    input.classList.toggle('input-invalid', invalid);
    input.setAttribute('aria-invalid', invalid ? 'true' : 'false');
}

// ── Análise de URL ────────────────────────────────

async function analyzeUrl() {
    const urlInput = document.getElementById('url-input');
    const btn = document.getElementById('analyze-btn');
    const url = urlInput.value.trim();

    const validationError = validateUrlInput(url);
    if (validationError) {
        showError(validationError);
        setUrlInputInvalid(urlInput, true);
        urlInput.focus();
        return;
    }
    setUrlInputInvalid(urlInput, false);

    showLoading(btn);
    clearError();

    try {
        const response = await fetch('/api/analyze/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();

        if (!response.ok) { showError(data.error || 'Erro ao analisar o URL.'); return; }
        if (typeof showUrlResult === 'function') showUrlResult(data);
    } catch {
        showError('Não foi possível ligar ao servidor. Verifica se o Flask está a correr.');
    } finally {
        hideLoading(btn, '<i class="bx bx-search-alt"></i> Analisar URL');
    }
}

// ── Análise de Mensagem ───────────────────────────

async function analyzeMessage() {
    const msgInput = document.getElementById('message-input');
    const btn = document.getElementById('analyze-msg-btn');
    const message = msgInput.value.trim();

    if (!message) { showError('Por favor, insere uma mensagem para analisar.'); return; }

    showLoading(btn);
    clearError();

    try {
        const response = await fetch('/api/analyze/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        const data = await response.json();

        if (!response.ok) { showError(data.error || 'Erro ao analisar a mensagem.'); return; }
        if (typeof showMessageResult === 'function') showMessageResult(data);
    } catch {
        showError('Não foi possível ligar ao servidor.');
    } finally {
        hideLoading(btn, '<i class="bx bx-search-alt"></i> Analisar Mensagem');
    }
}

// ── Sidebar (mobile) ──────────────────────────────

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('overlay');
    sidebar.classList.toggle('open');
    overlay.classList.toggle('show');
}

// ── Enter para submeter ───────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    const urlInput = document.getElementById('url-input');
    if (urlInput) {
        urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeUrl(); });
        // Limpa o estado de erro assim que o utilizador volta a escrever
        urlInput.addEventListener('input', () => { setUrlInputInvalid(urlInput, false); clearError(); });
    }
});
