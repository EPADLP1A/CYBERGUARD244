import os
import hashlib

# Extensões permitidas para upload — apenas formatos de documento e imagem seguros
ALLOWED_EXTENSIONS = {'.pdf', '.txt', '.docx', '.xlsx', '.png', '.jpg', '.jpeg'}

# Extensões executáveis ou interpretáveis consideradas perigosas
SUSPICIOUS_EXTENSIONS = {'.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.msi', '.scr', '.com', '.hta'}

# Limite de tamanho de upload: 1 MB (configurável via MAX_UPLOAD_SIZE no .env)
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


def analyze_file(file_path: str, filename: str) -> dict:
    """
    Analisa metadados de um ficheiro (extensão, tamanho, hash SHA-256).
    AVISO: O ficheiro NÃO é executado nem interpretado.
    Esta análise não substitui um antivírus.
    """
    indicators = []
    _, ext = os.path.splitext(filename.lower())

    # Verificar cada critério de risco e acumular indicadores
    _check_extension(ext, indicators)
    _check_double_extension(filename, indicators)
    _check_file_size(file_path, indicators)

    file_hash = _calculate_hash(file_path)
    file_size = os.path.getsize(file_path)

    return {
        'risk_level': _calculate_risk(indicators),
        'indicators': indicators,
        'file_hash': file_hash,
        'file_size': file_size,
        'extension': ext,
        'warning': (
            'Esta análise examina apenas metadados (extensão, tamanho). '
            'O ficheiro NÃO foi executado. Não substitui um antivírus real.'
        ),
        'summary': f'{len(indicators)} indicador(es) encontrado(s).'
    }


def validate_upload(filename: str, file_size: int) -> tuple:
    """
    Valida um ficheiro antes de o guardar no servidor.
    Retorna (válido: bool, mensagem_de_erro: str).
    Chamada antes de qualquer escrita em disco.
    """
    # Rejeitar ficheiros acima do limite para evitar ataques de exaustão de disco
    if file_size > MAX_FILE_SIZE:
        return False, f'Ficheiro demasiado grande. Máximo: {MAX_FILE_SIZE // 1024} KB'

    _, ext = os.path.splitext(filename.lower())
    if not ext:
        return False, 'O ficheiro não tem extensão'

    # Aceitar apenas extensões da lista de permitidos
    if ext not in ALLOWED_EXTENSIONS:
        allowed = ', '.join(sorted(ALLOWED_EXTENSIONS))
        return False, f'Tipo de ficheiro não suportado ({ext}). Permitidos: {allowed}'

    return True, 'OK'


def _check_extension(ext, indicators):
    """Assinala extensões executáveis ou de script como indicador de risco."""
    if ext in SUSPICIOUS_EXTENSIONS:
        indicators.append(f'Extensão potencialmente perigosa: {ext}')


def _check_double_extension(filename, indicators):
    """
    Deteta técnica comum de ofuscação: ficheiro.pdf.exe aparece como ficheiro.pdf
    mas é executável. Verifica a penúltima extensão.
    """
    parts = filename.rsplit('.', 2)
    if len(parts) == 3:
        inner_ext = '.' + parts[1].lower()
        if inner_ext in SUSPICIOUS_EXTENSIONS:
            indicators.append(f'Dupla extensão suspeita: {inner_ext} oculto no nome do ficheiro')


def _check_file_size(file_path, indicators):
    """Assinala ficheiros acima do limite como potencialmente problemáticos."""
    size = os.path.getsize(file_path)
    if size > MAX_FILE_SIZE:
        indicators.append(f'Ficheiro grande ({size // 1024} KB) — acima do limite recomendado')


def _calculate_hash(file_path: str) -> str:
    """
    Calcula o hash SHA-256 do ficheiro em blocos de 8 KB
    para não carregar ficheiros grandes inteiros na memória.
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def _calculate_risk(indicators: list) -> str:
    """Converte o número de indicadores num nível de risco: low / medium / high."""
    count = len(indicators)
    if count == 0:
        return 'low'
    elif count == 1:
        return 'medium'
    else:
        return 'high'
