"""
Testes para file_analyzer.py — inclui simulação de amostras EICAR.

A string EICAR é o standard de teste antivírus (EICAR Standard Anti-Virus Test File).
Aqui usamos o seu conteúdo como ficheiro de texto para testar o pipeline de análise
sem executar código malicioso real. O analisador examina apenas metadados, pelo que
o conteúdo do ficheiro não é interpretado.
"""
import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.file_analyzer import analyze_file, validate_upload, MAX_FILE_SIZE

# String EICAR oficial — inofensiva como texto, reconhecida por antivírus reais
EICAR_STRING = (
    r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)


def _make_temp_file(content: bytes, suffix: str) -> str:
    """Cria um ficheiro temporário e devolve o seu caminho."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content)
    os.close(fd)
    return path


# ── Testes de validação de upload ────────────────────────────────────────────

def test_ficheiro_valido_aceite():
    valido, msg = validate_upload('relatorio.pdf', 512)
    assert valido, f'Devia aceitar .pdf: {msg}'


def test_extensao_nao_permitida_rejeitada():
    valido, msg = validate_upload('malware.exe', 100)
    assert not valido
    assert 'não suportado' in msg.lower()


def test_sem_extensao_rejeitado():
    valido, msg = validate_upload('ficheiro_sem_ext', 100)
    assert not valido


def test_tamanho_acima_limite_rejeitado():
    valido, msg = validate_upload('grande.pdf', MAX_FILE_SIZE + 1)
    assert not valido
    assert 'grande' in msg.lower()


def test_tamanho_no_limite_aceite():
    valido, msg = validate_upload('exato.txt', MAX_FILE_SIZE)
    assert valido


# ── Testes de análise de metadados ───────────────────────────────────────────

def test_ficheiro_txt_limpo():
    path = _make_temp_file(b'conteudo normal', '.txt')
    try:
        result = analyze_file(path, 'documento.txt')
        assert result['risk_level'] == 'low'
        assert result['indicators'] == []
    finally:
        os.remove(path)


def test_dupla_extensao_detectada():
    path = _make_temp_file(b'conteudo', '.txt')
    try:
        result = analyze_file(path, 'factura.exe.pdf')
        assert any('dupla' in i.lower() for i in result['indicators'])
    finally:
        os.remove(path)


def test_hash_sha256_presente():
    path = _make_temp_file(b'dados', '.txt')
    try:
        result = analyze_file(path, 'dados.txt')
        assert len(result['file_hash']) == 64, 'SHA-256 deve ter 64 caracteres hex'
    finally:
        os.remove(path)


# ── Testes com amostra EICAR ─────────────────────────────────────────────────

def test_eicar_como_txt_risco_baixo():
    """
    Guardado como .txt, o conteúdo EICAR não aciona nenhum indicador de metadados
    porque o analisador examina extensão e tamanho, não o conteúdo.
    Resultado esperado: low risk (sem indicadores).
    """
    path = _make_temp_file(EICAR_STRING.encode(), '.txt')
    try:
        result = analyze_file(path, 'eicar_test.txt')
        assert result['risk_level'] == 'low'
        assert result['extension'] == '.txt'
    finally:
        os.remove(path)


def test_eicar_como_exe_risco_alto():
    """
    Guardado como .exe, o analisador deteta a extensão executável.
    Resultado esperado: indicador de extensão perigosa, risco médio ou alto.
    """
    path = _make_temp_file(EICAR_STRING.encode(), '.exe')
    try:
        result = analyze_file(path, 'eicar_test.exe')
        assert any('perigosa' in i.lower() for i in result['indicators'])
        assert result['risk_level'] in ('medium', 'high')
    finally:
        os.remove(path)


def test_eicar_dupla_extensao():
    """
    eicar_test.exe.pdf deve acionar o indicador de dupla extensão,
    mesmo que a extensão final seja .pdf.
    """
    path = _make_temp_file(EICAR_STRING.encode(), '.pdf')
    try:
        result = analyze_file(path, 'eicar_test.exe.pdf')
        assert any('dupla' in i.lower() for i in result['indicators'])
    finally:
        os.remove(path)


# ── Executar sem pytest ───────────────────────────────────────────────────────

if __name__ == '__main__':
    testes = [
        test_ficheiro_valido_aceite,
        test_extensao_nao_permitida_rejeitada,
        test_sem_extensao_rejeitado,
        test_tamanho_acima_limite_rejeitado,
        test_tamanho_no_limite_aceite,
        test_ficheiro_txt_limpo,
        test_dupla_extensao_detectada,
        test_hash_sha256_presente,
        test_eicar_como_txt_risco_baixo,
        test_eicar_como_exe_risco_alto,
        test_eicar_dupla_extensao,
    ]
    ok = fail = 0
    for t in testes:
        try:
            t()
            print(f'  ✓  {t.__name__}')
            ok += 1
        except Exception as e:
            print(f'  ✗  {t.__name__}: {e}')
            fail += 1
    print(f'\n{ok} passou · {fail} falhou')
