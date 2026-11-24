# CyberGuard AI

A digital security platform that analyzes URLs, messages, and files for threats using the VirusTotal API and local heuristic analysis.

## Features

- **URL Analysis** — checks suspicious links via VirusTotal (72+ engines)
- **Message Analysis** — detects phishing, fake urgency, and shortened links
- **File Analysis** — upload and scan with SHA-256 hash + VirusTotal
- **Scan History** — local log of recent scans (localStorage)
- **Heuristic Fallback** — offline analysis when the API is unavailable

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML + CSS + JS (single-file) |
| External API | VirusTotal v3 |
| Backend (optional) | Python / Flask |

## Project Structure

```
/
├── index.html              # Frontend autónomo (abre diretamente no browser)
├── cyberguard-ai/
│   ├── app.py              # Servidor Flask (páginas + API)
│   ├── requirements.txt
│   ├── .env.example        # Modelo do ficheiro de configuração
│   ├── database/db.py      # Histórico em SQLite
│   ├── services/
│   │   ├── url_analyzer.py
│   │   ├── message_analyzer.py
│   │   ├── file_analyzer.py
│   │   └── claude_service.py
│   ├── templates/          # Páginas HTML (Jinja2)
│   ├── static/             # CSS e JavaScript
│   └── tests/
│       ├── data/           # Listas de URLs maliciosos/seguros para testes
│       ├── test_url_analyzer.py
│       ├── test_url_malicious.py
│       ├── test_message_analyzer.py
│       └── test_file_analyzer.py
```

## Ambiente de desenvolvimento local

### Pré-requisitos

| Ferramenta | Versão | Verificar com |
|------------|--------|---------------|
| Python | 3.10 ou superior | `python --version` |
| pip | incluído com o Python | `pip --version` |
| Git | qualquer versão recente | `git --version` |

### 1. Clonar o repositório

```bash
git clone https://github.com/EPADLP1A/CYBERGUARD244.git
cd CYBERGUARD244/cyberguard-ai
```

### 2. Criar e ativar um ambiente virtual

```bash
# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

Quando o ambiente está ativo aparece `(venv)` no início da linha do terminal.

### 3. Instalar as dependências

```bash
pip install -r requirements.txt
pip install pytest          # necessário apenas para correr os testes
```

### 4. Configurar as variáveis de ambiente

```bash
# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```

Abre o `.env` e preenche os valores:

| Variável | Obrigatória | Descrição |
|----------|-------------|-----------|
| `CLAUDE_API_KEY` | Não | Chave da API Claude para as explicações da IA. Sem ela, a análise funciona na mesma, mas a explicação mostra um aviso. |
| `CLAUDE_MODEL` | Não | Modelo usado (por omissão `claude-haiku-5-5`). |
| `FLASK_ENV` / `FLASK_DEBUG` | Não | `development` / `1` para recarregar automaticamente ao editar código. |
| `MAX_UPLOAD_SIZE` | Não | Tamanho máximo de upload em bytes (por omissão `1048576` = 1 MB). |

> O ficheiro `.env` está no `.gitignore` — **nunca o adiciones ao Git**.

### 5. Arrancar o servidor

```bash
python app.py
```

Abre [http://localhost:5000](http://localhost:5000). A base de dados SQLite (`database/cyberguard.db`) é criada automaticamente no primeiro arranque.

### 6. Correr os testes

```bash
python -m pytest -v                     # todos os testes
python tests/test_url_malicious.py      # relatório de deteção de URLs maliciosos
```

### Frontend autónomo (sem Flask)

O `index.html` na raiz funciona sozinho: basta abri-lo no browser. Usa a API do VirusTotal diretamente e, se esta não estiver disponível, recorre à análise heurística local.

### Problemas comuns

| Problema | Solução |
|----------|---------|
| `ModuleNotFoundError: No module named 'flask'` | O ambiente virtual não está ativo — repete o passo 2. |
| `Address already in use` (porta 5000) | Outro programa usa a porta. No macOS desativa o "AirPlay Receiver" ou altera a porta no fim do `app.py`. |
| Scripts bloqueados no PowerShell | Corre `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |
| "Chave da API não configurada" | Normal sem `CLAUDE_API_KEY`; preenche-a no `.env` se quiseres as explicações da IA. |

## Rotas da API (Flask)

Todas as rotas de API devolvem JSON. Em caso de erro a resposta tem o formato `{"error": "mensagem"}`.

### Resumo

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/` | Página inicial (últimas 5 análises) |
| `GET` | `/url-analysis` | Página de análise de URL |
| `GET` | `/message-analysis` | Página de análise de mensagens |
| `GET` | `/file-analysis` | Página de análise de ficheiros |
| `GET` | `/history` | Página de histórico (últimas 100 análises) |
| `POST` | `/api/analyze/url` | Analisa um URL |
| `POST` | `/api/analyze/message` | Analisa uma mensagem de texto |
| `POST` | `/api/analyze/file` | Analisa um ficheiro enviado |
| `GET` | `/api/history` | Lista o histórico de análises |
| `DELETE` | `/api/history` | Apaga todo o histórico |
| `GET` | `/api/history/export/csv` | Descarrega o histórico em CSV |

Valores possíveis de `risk_level`: `low` (0 indicadores), `medium` (1–2), `high` (3 ou mais).

### `POST /api/analyze/url`

Analisa um URL sem o visitar. O URL é validado antes da análise: tem de ser texto, ter no máximo 2000 caracteres, não ter espaços, usar `http`/`https` (ou nenhum esquema) e ter um domínio válido.

**Request**

```http
POST /api/analyze/url
Content-Type: application/json

{ "url": "http://paypal-verify.xyz/login" }
```

**Response `200`**

```json
{
  "risk_level": "high",
  "indicators": [
    "Ligação não encriptada (HTTP em vez de HTTPS)",
    "Extensão de domínio associada a abusos: .xyz",
    "O domínio pode estar a imitar a marca \"paypal\""
  ],
  "summary": "3 indicador(es) encontrado(s).",
  "parsed": { "scheme": "http", "domain": "paypal-verify.xyz", "path": "/login" },
  "ai_explanation": "Este link apresenta vários sinais de phishing..."
}
```

**Erros `400`**

| Situação | `error` |
|----------|---------|
| Campo `url` em falta | `URL não fornecido` |
| `url` não é texto | `O URL tem de ser texto` |
| Vazio | `URL não pode estar vazio` |
| Mais de 2000 caracteres | `URL demasiado longo (máximo 2000 caracteres)` |
| Contém espaços | `O URL não pode conter espaços` |
| Esquema não suportado (`javascript:`, `ftp://`…) | `Apenas são suportados URLs http:// ou https://` |
| Sem domínio / domínio inválido | `O URL não tem um domínio válido` / `O domínio do URL não é válido` |

```bash
curl -X POST http://localhost:5000/api/analyze/url \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal-verify.xyz/login"}'
```

### `POST /api/analyze/message`

Procura sinais de phishing num texto (urgência, pedidos de credenciais, links encurtados…). Só os primeiros 500 caracteres são guardados no histórico.

**Request**

```json
{ "message": "URGENTE! A sua conta será bloqueada. Clique aqui: http://bit.ly/abc" }
```

**Response `200`**

```json
{
  "risk_level": "high",
  "indicators": [
    "Linguagem de urgência — técnica comum para pressionar a vítima a agir sem pensar",
    "Link encurtado encontrado — o destino real está escondido"
  ],
  "summary": "2 indicador(es) encontrado(s).",
  "ai_explanation": "..."
}
```

**Erros `400`:** `Mensagem não fornecida` · `Mensagem não pode estar vazia` · `Mensagem demasiado longa (máximo 10 000 caracteres)`

### `POST /api/analyze/file`

Analisa os metadados de um ficheiro (extensão, dupla extensão, tamanho) e calcula o hash SHA-256. O ficheiro **não é executado** e é apagado logo após a análise.

- Formato: `multipart/form-data`, campo `file`
- Extensões permitidas: `.pdf .txt .docx .xlsx .png .jpg .jpeg`
- Tamanho máximo: 1 MB (`MAX_UPLOAD_SIZE`)

```bash
curl -X POST http://localhost:5000/api/analyze/file -F "file=@relatorio.pdf"
```

**Response `200`**

```json
{
  "risk_level": "low",
  "indicators": [],
  "file_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  "file_size": 5,
  "extension": ".pdf",
  "summary": "0 indicador(es) encontrado(s).",
  "warning": "Esta análise examina apenas metadados (extensão, tamanho). O ficheiro NÃO foi executado. Não substitui um antivírus real.",
  "ai_explanation": "..."
}
```

**Erros:** `400` — `Nenhum ficheiro enviado` · `Nenhum ficheiro selecionado` · `O ficheiro não tem extensão` · `Tipo de ficheiro não suportado (.exe). Permitidos: ...` · `Ficheiro demasiado grande. Máximo: 1024 KB`; `413` — `Ficheiro demasiado grande` (excede `MAX_UPLOAD_SIZE`).

### `GET /api/history`

Devolve as últimas 100 análises, da mais recente para a mais antiga. O campo `indicators` vem como texto JSON.

```json
{
  "history": [
    {
      "id": 3,
      "analysis_type": "url",
      "content": "http://paypal-verify.xyz/login",
      "risk_level": "high",
      "indicators": "[\"Ligação não encriptada (HTTP em vez de HTTPS)\", \"...\"]",
      "ai_explanation": "...",
      "created_at": "2026-11-23T17:29:31.217780"
    }
  ]
}
```

### `DELETE /api/history`

Apaga todas as análises guardadas.

```json
{ "message": "Histórico apagado com sucesso" }
```

### `GET /api/history/export/csv`

Descarrega `historico_cyberguard.csv` com as colunas `id, tipo, conteudo, risco, indicadores, data`.

```bash
curl -o historico.csv http://localhost:5000/api/history/export/csv
```

### Erros globais

| Código | Resposta |
|--------|----------|
| `404` | Mostra a página inicial |
| `413` | `{"error": "Ficheiro demasiado grande"}` |
| `500` | `{"error": "Erro interno do servidor"}` |

## Design

Dark editorial aesthetic with animated wave background (red & white), Liquid Glass panels, Instrument Serif typography, and VirusTotal API integration.

---

Projeto Escolar 2024/25 · 10.º ano · Programação e Sistemas de Informação
