# secret-scanner/web/app.py

import os
import tempfile
import shutil
import yaml
from typing import Dict, Any
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

# Добавляем путь к корневой директории, чтобы импортировать сканер
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.core.engine import ScanEngine
from scanner.rules.rule_loader import RuleLoader

# --- Инициализация приложения и сканера ---

app = Flask(__name__)
app.secret_key = 'super-secret-key-for-flask-flashes' # Ключ для flash-сообщений
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Ограничение размера загружаемого файла (16 MB)

def get_scanner_engine() -> ScanEngine:
    """Инициализирует и возвращает экземпляр движка сканера."""
    config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config'))
    with open(os.path.join(config_dir, 'settings.yaml'), 'r', encoding='utf-8') as f:
        config: Dict[str, Any] = yaml.safe_load(f)
    config['rule_paths'] = [
        os.path.join(config_dir, 'default_rules.yaml'),
        os.path.join(config_dir, 'ru_rules.yaml')
    ]
    return ScanEngine(config)

# Создаем один экземпляр движка при старте приложения
scanner_engine = get_scanner_engine()

# Загружаем правила для передачи в HTML-шаблон
rules = RuleLoader(scanner_engine.config['rule_paths']).load_rules()
rules_map = {rule.id: rule for rule in rules}

@app.route('/')
def index():
    """Отображает главную страницу с формой загрузки."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Обрабатывает загрузку ZIP-архива, запускает сканирование и показывает отчет."""
    if 'project_zip' not in request.files:
        flash('Файл не был отправлен.', 'error')
        return redirect(url_for('index'))
    
    file = request.files['project_zip']
    
    if file.filename == '':
        flash('Файл не выбран.', 'error')
        return redirect(url_for('index'))
    
    # ИСПРАВЛЕНО: Полностью переписана логика обработки
    if file and file.filename.endswith('.zip'):
        filename = secure_filename(file.filename)
        temp_dir = tempfile.mkdtemp() # Создаем безопасную временную директорию
        try:
            zip_path = os.path.join(temp_dir, filename)
            file.save(zip_path)
            
            extract_dir = os.path.join(temp_dir, 'extracted_project')
            os.makedirs(extract_dir, exist_ok=True)
            
            # Распаковка архива
            shutil.unpack_archive(zip_path, extract_dir)
            
            # Запуск сканирования на распакованной директории
            # Для веб-версии отключаем сканирование Git по умолчанию для скорости
            findings = scanner_engine.run(extract_dir, scan_git=False)
            
            # Добавляем полные данные о правилах к находкам для рендеринга в шаблоне
            findings_with_rules = [
                {"finding": f, "rule": rules_map.get(f.rule_id)} for f in findings
            ]
            
            return render_template(
                'report.html',
                findings_with_rules=findings_with_rules,
                title=f"Отчет для {filename}"
            )
        except Exception as e:
            flash(f'Произошла ошибка при обработке файла: {e}', 'error')
            return redirect(url_for('index'))
        finally:
            # Гарантированно удаляем временную директорию со всем содержимым
            shutil.rmtree(temp_dir)
    else:
        # Если файл не .zip, сообщаем об ошибке
        flash('Пожалуйста, загрузите корректный ZIP-архив.', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    # Для локального запуска. В продакшене используется gunicorn или другой WSGI-сервер.
    app.run(debug=True, host='0.0.0.0', port=5000)
