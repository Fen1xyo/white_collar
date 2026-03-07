import requests
from ..core.finding import Finding

# Конфигурация Ollama
OLLAMA_URL = "http://localhost:11434/api/generate"
# Рекомендуется qwen2.5:3b для хорошего соотношения скорости и качества
MODEL = "qwen2.5-coder:1.5b"

def get_fix_suggestion(finding: Finding) -> str:
    """
    Отправляет находку в локальную LLM (Ollama) и получает конкретный патч.
    """
    prompt = f"""Перепиши код на Python, используя os.environ.get().
Строка: {finding.line_content.strip()}
Секрет: {finding.secret}

Выведи ТОЛЬКО 2 строки (без пояснений и кавычек):
СТАЛО: <код>
ENV: export <ПЕРЕМЕННАЯ>="<секрет>"
"""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.0, 
                    "num_predict": 100, 
                    "num_ctx": 1024, 
                    "top_k": 1, 
                },
                "keep_alive": "30m"
            },
            timeout=60,
        )
        if response.status_code == 200:
            result = response.json().get("response", "").strip()
            return result if result else "[LLM вернула пустой ответ]"
        return f"[LLM ошибка сервера: HTTP {response.status_code}]"
    except requests.exceptions.ConnectionError:
        return "[LLM недоступна: проверьте, запущен ли 'ollama serve']"
    except Exception as e:
        return f"[Критическая ошибка LLM: {e}]"
