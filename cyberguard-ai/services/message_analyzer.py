import re

URGENCY_PATTERNS = [
    r'urgente', r'imediatamente', r'agora mesmo',
    r'nas pr[oó]ximas \d+ horas',
    r'a sua conta (ser[aá]|foi) (suspensa|bloqueada)',
    r'a[çc][aã]o necess[aá]ria', r'prazo'
]

CREDENTIAL_PATTERNS = [
    r'(introduza|confirme|verifique|atualize) (a sua )?(password|palavra.passe|pin|c[oó]digo)',
    r'(clique|aceda) (aqui|no link) para (verificar|confirmar|atualizar)',
    r'dados (banc[aá]rios|de acesso|de login|pessoais)',
    r'n[uú]mero (do cart[aã]o|de conta|contribuinte)'
]

# Domínios de encurtadores de links (comparados com o domínio exato, para
# evitar falsos positivos como "t.co" dentro de "microsoft.com")
LINK_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'rebrand.ly', 'cutt.ly', 'shorturl.at']

# Deteta links com ou sem esquema: "https://x.com/a", "www.x.com", "bit.ly/abc".
# Exige um TLD só com letras para não apanhar números como "3.50".
_LINK_RE = re.compile(
    r'(?:https?://)?(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?::\d+)?(?:/[^\s]*)?',
    re.IGNORECASE
)
GENERIC_GREETINGS = ['caro cliente', 'prezado utilizador', 'dear customer', 'valued customer', 'caro utilizador']


def analyze_message(text: str) -> dict:
    """Analisa uma mensagem em busca de sinais de phishing e engenharia social."""
    indicators = []

    _check_urgency(text, indicators)
    _check_credential_request(text, indicators)
    _check_suspicious_links(text, indicators)
    _check_generic_greeting(text, indicators)

    risk_level = _calculate_risk(indicators)

    return {
        'risk_level': risk_level,
        'indicators': indicators,
        'summary': f'{len(indicators)} indicador(es) encontrado(s).'
    }


def _check_urgency(text, indicators):
    lower = text.lower()
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, lower):
            indicators.append('Linguagem de urgência — técnica comum para pressionar a vítima a agir sem pensar')
            break


def _check_credential_request(text, indicators):
    lower = text.lower()
    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, lower):
            indicators.append('Pedido de credenciais (password, PIN ou códigos) ou dados pessoais/bancários')
            break


def _extract_host(link: str) -> str:
    """Devolve o domínio de um link (sem esquema, porta, caminho nem pontuação final)."""
    host = re.sub(r'^https?://', '', link, flags=re.IGNORECASE)
    host = re.split(r'[/:?#]', host, maxsplit=1)[0]
    return host.lower().rstrip('.')


def _check_suspicious_links(text, indicators):
    """
    Procura links encurtados ou com IP direto.

    Os links são detetados mesmo sem "http://" (ex.: "bit.ly/abc123"),
    porque as mensagens de phishing por SMS raramente incluem o esquema.
    """
    for match in _LINK_RE.finditer(text):
        host = _extract_host(match.group(0))
        if any(host == s or host.endswith('.' + s) for s in LINK_SHORTENERS):
            indicators.append('Link encurtado encontrado — o destino real está escondido')
            break
        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
            indicators.append('Link com endereço IP em vez de domínio')
            break


def _check_generic_greeting(text, indicators):
    lower = text.lower()
    for greeting in GENERIC_GREETINGS:
        if greeting in lower:
            indicators.append('Saudação genérica — mensagens legítimas geralmente usam o teu nome')
            break


def _calculate_risk(indicators: list) -> str:
    count = len(indicators)
    if count == 0:
        return 'low'
    elif count <= 1:
        return 'medium'
    else:
        return 'high'
