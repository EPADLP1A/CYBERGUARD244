"""
Testes de eficácia do url_analyzer com listas de URLs conhecidos (issue #47).

- tests/data/malicious_urls.txt → URLs com padrões reais de phishing
- tests/data/safe_urls.txt      → URLs legítimos (controlo de falsos positivos)

Executar:  python -m pytest tests/test_url_malicious.py -v
      ou:  python tests/test_url_malicious.py   (mostra relatório detalhado)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.url_analyzer import analyze_url, validate_url

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

# Percentagem mínima de URLs maliciosos que devem ser classificados como 'high'
MIN_HIGH_RATE = 0.70


def _load_urls(filename):
    """Lê um ficheiro de URLs ignorando comentários (#) e linhas vazias."""
    urls = []
    with open(os.path.join(DATA_DIR, filename), encoding='utf-8') as f:
        for line in f:
            line = line.split('  #')[0].strip()  # remove comentário inline
            if line and not line.startswith('#'):
                urls.append(line)
    return urls


MALICIOUS = _load_urls('malicious_urls.txt')
SAFE = _load_urls('safe_urls.txt')


def test_listas_carregadas():
    assert len(MALICIOUS) >= 20, 'A lista de URLs maliciosos devia ter pelo menos 20 entradas'
    assert len(SAFE) >= 10, 'A lista de URLs seguros devia ter pelo menos 10 entradas'


def test_malicious_passam_validacao():
    """Os URLs maliciosos têm de ser aceites pela validação (senão nem são analisados)."""
    rejeitados = [u for u in MALICIOUS if not validate_url(u)[0]]
    assert not rejeitados, f'URLs rejeitados pela validação: {rejeitados}'


def test_todos_malicious_detetados():
    """Nenhum URL malicioso pode ser classificado como 'low' (falso negativo)."""
    falhados = [u for u in MALICIOUS if analyze_url(u)['risk_level'] == 'low']
    assert not falhados, f'URLs maliciosos não detetados: {falhados}'


def test_malicious_tem_indicadores():
    sem_indicadores = [u for u in MALICIOUS if not analyze_url(u)['indicators']]
    assert not sem_indicadores, f'URLs sem nenhum indicador: {sem_indicadores}'


def test_taxa_risco_elevado():
    """Pelo menos 70% dos URLs maliciosos devem ser classificados como 'high'."""
    high = sum(1 for u in MALICIOUS if analyze_url(u)['risk_level'] == 'high')
    taxa = high / len(MALICIOUS)
    assert taxa >= MIN_HIGH_RATE, f'Apenas {taxa:.0%} classificados como risco elevado (mínimo {MIN_HIGH_RATE:.0%})'


def test_safe_sem_falsos_positivos():
    """URLs legítimos devem ser 'low' — controlo de falsos positivos."""
    falsos_positivos = {u: analyze_url(u)['indicators'] for u in SAFE if analyze_url(u)['risk_level'] != 'low'}
    assert not falsos_positivos, f'Falsos positivos: {falsos_positivos}'


# ── Casos específicos por técnica ─────────────────

def test_truque_arroba_com_marca():
    r = analyze_url('http://www.cgd.pt@login-cgd-seguro.ml/')
    assert r['risk_level'] == 'high'
    assert any('@' in i for i in r['indicators'])

def test_ip_com_credenciais():
    r = analyze_url('http://user:pass@91.214.124.20/google/drive/share')
    assert any('IP' in i for i in r['indicators']), 'Devia detetar o IP mesmo com user:pass@'

def test_subdominios_a_imitar_marca():
    r = analyze_url('http://google.com.drive.docs.share.file-view.xyz/d/1aBcD')
    assert any('subdomínios' in i for i in r['indicators'])
    assert r['risk_level'] == 'high'

def test_tld_com_porta():
    r = analyze_url('http://banco-seguro.xyz:8080/login')
    assert any('extensão' in i.lower() for i in r['indicators']), 'A porta não deve esconder o TLD'


# ── Validação de input (issue #46) ────────────────

def test_validacao_rejeita_invalidos():
    for bad in ['', '   ', 'javascript:alert(1)', 'ftp://x.com', 'data:text/html,hi',
                'not a url', 'http://', 'http://x', 'x' * 2001, None, 123]:
        assert validate_url(bad)[0] is False, f'Devia rejeitar {bad!r}'

def test_validacao_aceita_validos():
    for ok in ['exemplo.com', 'https://google.com', 'http://192.168.1.1/login',
               'exemplo.com:8080/x', 'localhost:5000', 'http://café.pt']:
        assert validate_url(ok)[0] is True, f'Devia aceitar {ok!r}'

def test_validacao_remove_espacos_nas_pontas():
    assert validate_url('  https://google.com  ') == (True, 'https://google.com')


# ── Executar sem pytest (com relatório) ───────────
if __name__ == '__main__':
    print('Relatório de deteção — URLs maliciosos\n')
    contagem = {'low': 0, 'medium': 0, 'high': 0, 'unknown': 0}
    for u in MALICIOUS:
        r = analyze_url(u)
        contagem[r['risk_level']] += 1
        print(f"  [{r['risk_level']:^6}] {len(r['indicators'])} ind. · {u[:70]}")
    total = len(MALICIOUS)
    print(f"\nDetetados: {total - contagem['low']}/{total} "
          f"({(total - contagem['low']) / total:.0%}) · risco elevado: {contagem['high']}/{total}")

    fp = sum(1 for u in SAFE if analyze_url(u)['risk_level'] != 'low')
    print(f'Falsos positivos em URLs seguros: {fp}/{len(SAFE)}\n')

    testes = [v for k, v in dict(globals()).items() if k.startswith('test_') and callable(v)]
    ok = fail = 0
    for t in testes:
        try:
            t(); print(f'  ✓  {t.__name__}'); ok += 1
        except Exception as e:
            print(f'  ✗  {t.__name__}: {e}'); fail += 1
    print(f'\n{ok} passou · {fail} falhou')
