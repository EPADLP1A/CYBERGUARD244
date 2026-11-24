"""
Módulo de análise heurística de URLs do CyberGuard AI.

Este módulo examina um URL *sem o visitar* e procura padrões normalmente
associados a phishing e fraude (HTTP sem encriptação, IP em vez de domínio,
extensões de domínio abusadas, imitação de marcas, etc.).

Fluxo principal:
    1. ``validate_url()``  — confirma que o input tem um formato aceitável
       (usado pela rota ``POST /api/analyze/url`` antes de analisar).
    2. ``analyze_url()``   — normaliza o URL, corre todas as verificações
       ``_check_*`` e calcula o nível de risco final.

Cada função ``_check_*`` recebe o URL já decomposto (``ParseResult``) e
acrescenta mensagens em português à lista ``indicators`` quando encontra
um sinal suspeito. Isto permite adicionar novas regras facilmente: basta
criar uma nova função ``_check_*`` e chamá-la em ``analyze_url()``.
"""

import re
from urllib.parse import urlparse

# ─── Configuração ──────────────────────────────────────────────────────────

# Extensões de domínio (TLD) baratas ou gratuitas, muito usadas em campanhas
# de phishing por serem fáceis de registar em massa.
SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.loan', '.work', '.gq', '.ml', '.cf', '.ga', '.tk']

# Marcas frequentemente imitadas. Se uma destas palavras aparecer no domínio
# mas o domínio não for o oficial (<marca>.com), assinalamos possível imitação.
BRAND_KEYWORDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
    'facebook', 'instagram', 'banco', 'cgd', 'bpi', 'millennium', 'santander'
]

# Limites usados na validação de input e nas heurísticas.
MAX_URL_LENGTH = 2000          # acima disto o pedido é rejeitado (validação)
LONG_URL_THRESHOLD = 100       # acima disto o URL é considerado "muito longo"
MAX_DOTS_IN_HOST = 3           # mais pontos do que isto = demasiados subdomínios

# Esquemas que aceitamos analisar. Outros (javascript:, data:, file:, ftp:...)
# são rejeitados na validação porque não são links web normais.
ALLOWED_SCHEMES = ('http', 'https')

# Regex simples para um nome de host válido: letras, dígitos, hífens e pontos,
# com pelo menos um ponto (ex.: "exemplo.com") ou um endereço IPv4.
_HOST_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$', re.IGNORECASE)
_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


# ─── Validação de input ────────────────────────────────────────────────────

def validate_url(url) -> tuple:
    """
    Valida o URL introduzido pelo utilizador antes de ser analisado.

    A validação é propositadamente tolerante: aceita URLs sem esquema
    (ex.: ``exemplo.com``) porque os utilizadores copiam muitas vezes só o
    domínio. Rejeita apenas inputs que não fazem sentido analisar.

    Args:
        url: valor recebido do formulário / JSON (pode não ser string).

    Returns:
        tuple: ``(True, url_limpo)`` se for válido, ou
               ``(False, mensagem_de_erro)`` caso contrário.
    """
    if not isinstance(url, str):
        return False, 'O URL tem de ser texto'

    url = url.strip()
    if not url:
        return False, 'URL não pode estar vazio'
    if len(url) > MAX_URL_LENGTH:
        return False, f'URL demasiado longo (máximo {MAX_URL_LENGTH} caracteres)'
    if any(c.isspace() for c in url):
        return False, 'O URL não pode conter espaços'

    # Detetar esquema explícito (ex.: "javascript:", "ftp://")
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):', url)
    if scheme_match and scheme_match.group(1).lower() not in ALLOWED_SCHEMES:
        # "exemplo.com:8080" também casa com a regex — só rejeitamos se não
        # parecer um host com porta.
        if not re.match(r'^[^/]+:\d+', url):
            return False, 'Apenas são suportados URLs http:// ou https://'

    normalised = url if url.lower().startswith(('http://', 'https://')) else 'http://' + url
    try:
        parsed = urlparse(normalised)
        port = parsed.port  # levanta ValueError se a porta for inválida
    except ValueError:
        return False, 'Formato de URL inválido'

    host = parsed.hostname or ''
    if not host:
        return False, 'O URL não tem um domínio válido'
    # Domínios com caracteres não-ASCII (ex.: "pаypal.com" com "а" cirílico)
    # são convertidos para punycode — queremos analisá-los, não rejeitá-los,
    # porque são uma técnica de phishing conhecida (ataque homográfico).
    try:
        ascii_host = host.encode('idna').decode('ascii')
    except UnicodeError:
        return False, 'O domínio do URL não é válido'
    if not (_HOST_RE.match(ascii_host) or _IPV4_RE.match(host) or host == 'localhost'):
        return False, 'O domínio do URL não é válido'
    if port is not None and not (0 < port < 65536):
        return False, 'Porta inválida no URL'

    return True, url


# ─── Análise principal ─────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Analisa um URL e devolve indicadores de risco.

    O URL não é visitado: toda a análise é feita sobre o texto do endereço,
    o que torna esta função rápida e segura de usar mesmo sem internet.

    Args:
        url: endereço a analisar (com ou sem ``http://`` / ``https://``).

    Returns:
        dict com as chaves:
            - ``risk_level`` (str): ``'low'``, ``'medium'``, ``'high'`` ou ``'unknown'``
            - ``indicators`` (list[str]): sinais suspeitos encontrados
            - ``summary`` (str): resumo curto do resultado
            - ``parsed`` (dict): ``scheme``, ``domain`` e ``path`` do URL

    Exemplo:
        >>> analyze_url('http://paypal-login.xyz')['risk_level']
        'high'
    """
    indicators = []

    # Se o utilizador não indicou o esquema, assumimos http:// apenas para
    # conseguir decompor o URL (o _check_https vai depois assinalá-lo).
    try:
        normalised = url if url.startswith(('http://', 'https://')) else 'http://' + url
        parsed = urlparse(normalised)
    except Exception:
        return {
            'risk_level': 'unknown',
            'indicators': ['Não foi possível analisar o URL — formato inválido'],
            'summary': 'URL com formato inválido.',
            'parsed': {}
        }

    # Cada verificação acrescenta (ou não) mensagens à lista de indicadores.
    _check_https(parsed, indicators)
    _check_ip_host(parsed, indicators)
    _check_suspicious_tld(parsed, indicators)
    _check_brand_impersonation(parsed, indicators)
    _check_url_length(url, indicators)
    _check_special_chars(parsed, indicators)
    _check_many_subdomains(parsed, indicators)

    risk_level = _calculate_risk(indicators)

    return {
        'risk_level': risk_level,
        'indicators': indicators,
        'summary': f'{len(indicators)} indicador(es) encontrado(s).',
        'parsed': {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path
        }
    }


# ─── Verificações individuais ──────────────────────────────────────────────

def _host_only(parsed) -> str:
    """Devolve só o nome do host, sem utilizador (``user@``) nem porta (``:8080``)."""
    host = parsed.netloc.rsplit('@', 1)[-1]
    return host.split(':')[0].lower()


def _check_https(parsed, indicators):
    """Assinala ligações HTTP, que não são encriptadas e permitem intercetar dados."""
    if parsed.scheme == 'http':
        indicators.append('Ligação não encriptada (HTTP em vez de HTTPS)')


def _check_ip_host(parsed, indicators):
    """
    Assinala URLs que usam um endereço IP (ex.: ``http://192.168.1.1``).

    Sites legítimos quase sempre usam um nome de domínio; um IP direto é
    típico de servidores temporários montados para ataques.
    """
    host = _host_only(parsed)
    if _IPV4_RE.match(host):
        indicators.append('O endereço usa um IP em vez de um nome de domínio')


def _check_suspicious_tld(parsed, indicators):
    """Assinala domínios terminados numa das extensões em ``SUSPICIOUS_TLDS``."""
    host = _host_only(parsed)
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            indicators.append(f'Extensão de domínio associada a abusos: {tld}')
            break  # basta um indicador de TLD


def _check_brand_impersonation(parsed, indicators):
    """
    Deteta possíveis imitações de marcas conhecidas.

    Exemplo: ``paypal-secure.com`` contém "paypal" mas não é ``paypal.com``
    nem um subdomínio oficial (``www.paypal.com``), por isso é assinalado.
    """
    host = _host_only(parsed)
    for brand in BRAND_KEYWORDS:
        in_host = brand in host
        is_official = host == f'{brand}.com' or host.endswith(f'.{brand}.com')
        if in_host and not is_official:
            indicators.append(f'O domínio pode estar a imitar a marca "{brand}"')


def _check_url_length(url, indicators):
    """URLs muito longos são usados para esconder o domínio real no meio de texto."""
    if len(url) > LONG_URL_THRESHOLD:
        indicators.append(f'URL muito longo ({len(url)} caracteres) — pode esconder o destino real')


def _check_special_chars(parsed, indicators):
    """
    Assinala o símbolo ``@`` na parte do domínio.

    Num URL como ``http://banco.pt@site-malicioso.com`` o browser ignora tudo
    antes do ``@`` e abre ``site-malicioso.com`` — truque clássico de phishing.
    """
    if '@' in parsed.netloc:
        indicators.append('Símbolo "@" no domínio — técnica comum de phishing')


def _check_many_subdomains(parsed, indicators):
    """
    Assinala hosts com muitos subdomínios.

    Ex.: ``login.paypal.com.conta.verificar.net`` tenta parecer ``paypal.com``
    mas o domínio verdadeiro é ``verificar.net``.
    """
    host = _host_only(parsed)
    if host.count('.') > MAX_DOTS_IN_HOST:
        indicators.append('Número elevado de subdomínios — pode tentar imitar um site legítimo')


# ─── Cálculo do risco ──────────────────────────────────────────────────────

def _calculate_risk(indicators: list) -> str:
    """
    Converte o número de indicadores num nível de risco.

    - 0 indicadores  → ``'low'``    (Baixo Risco)
    - 1–2 indicadores → ``'medium'`` (Requer Atenção)
    - 3 ou mais       → ``'high'``   (Risco Elevado)
    """
    count = len(indicators)
    if count == 0:
        return 'low'
    elif count <= 2:
        return 'medium'
    else:
        return 'high'
