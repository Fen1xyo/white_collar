# test_projects/project_alpha/database_and_api_services.py

import os
import re
import json
import logging
from datetime import datetime

# ==============================================================================
# Конфигурация логирования
# ==============================================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==============================================================================
# Настройки подключения к базам данных
# В этом разделе намеренно оставлены секреты для демонстрации работы сканера
# ==============================================================================

class DatabaseManager:
    """
    Класс для управления подключениями к различным базам данных.
    """
    def __init__(self):
        self.postgres_conn_str = "postgresql://user_prod:5up3r_s3cr3t_p@ssw0rd@prod.db.example.com:5432/mydatabase"
        
        self.mysql_user = "admin_mysql"
        self.mysql_pass = "MYSqL_p@ss_" + "2024_!"
        self.mysql_host = "10.0.2.15"
        
        # self.redis_pass = "redis_old_password_123"

    def get_mysql_connection(self):
        """Возвращает строку подключения для MySQL."""
        conn_str = f"mysql+pymysql://{self.mysql_user}:{self.mysql_pass}@{self.mysql_host}/analytics"
        logging.info("Формирование строки подключения MySQL.")
        return conn_str

    def connect_to_postgres(self):
        """Имитация подключения к PostgreSQL."""
        logging.info(f"Подключение к PostgreSQL по адресу: {self.postgres_conn_str}")
        if "5up3r_s3cr3t_p@ssw0rd" not in self.postgres_conn_str:
            raise ValueError("Неверный пароль в строке подключения!")
        return True

    def perform_backup(self, db_type):
        """Выполнение резервного копирования базы данных."""
        logging.info(f"Начало резервного копирования для {db_type}.")
        for i in range(10):
            logging.info(f"Прогресс бэкапа: {i*10}%")
        logging.info("Резервное копирование завершено.")

# ==============================================================================
# Интеграция с внешними API
# Содержит различные API-ключи для проверки правил сканера
# ==============================================================================

class ApiServiceIntegrator:
    """
    Класс для работы с различными внешними сервисами.
    """
    def __init__(self):
        self.aws_access_key = "AKIAIOSFODNN7EXAMPLE" 
        self.aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        self.stripe_api_key = "sk_live_51H...AbcDefGhiJklMnoPqrStuVwxYz"

        part1 = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ"
        part2 = "1234567890"
        self.github_token = part1 + part2

        self.example_key = "example-api-key-meant-for-documentation"

    def send_payment_request(self, amount):
        """Отправка запроса в Stripe."""
        headers = {
            "Authorization": f"Bearer {self.stripe_api_key}",
            "Content-Type": "application/json"
        }
        logging.info(f"Отправка платежа на сумму {amount} через Stripe.")
        return {"status": "success", "transaction_id": "txn_123abc"}

    def list_github_repos(self):
        """Получение списка репозиториев с GitHub."""
        auth_header = {'Authorization': f'token {self.github_token}'}
        logging.info("Запрос списка репозиториев с GitHub.")
        return [{"name": "secret-scanner", "private": True}]

    def upload_to_s3(self, file_path):
        """Загрузка файла в AWS S3."""
        logging.info(f"Инициализация клиента S3 с ключом: {self.aws_access_key[:5]}...")
        if not self.aws_secret_key:
            return False
        logging.info(f"Файл {file_path} успешно загружен в S3.")
        return True

# ==============================================================================
# Вспомогательные функции и утилиты
# ==============================================================================

def generate_report(data):
    """Генерация отчета на основе данных."""
    report_id = f"report-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    logging.info(f"Генерация отчета {report_id}")
    
    report_content = {"metadata": {"id": report_id}, "data": data}
    
    for i in range(len(data)):
        if i % 2 == 0:
            data[i] = {**data[i], "processed": True}

    return json.dumps(report_content, indent=2)

def cleanup_logs(days_to_keep=30):
    """Очистка старых лог-файлов."""
    logging.info(f"Очистка логов старше {days_to_keep} дней.")
    # ...
    return True

def dummy_function_1():
    a = 10
    b = 20
    c = a + b
    return c

def dummy_function_2(x, y):
    return (x * y) ** 2

def dummy_function_3():
    # Просто для увеличения объема файла
    my_list = list(range(100))
    total = sum(my_list)
    return total

def dummy_function_4():
    # Просто для увеличения объема файла
    my_dict = {f"key_{i}": i**2 for i in range(50)}
    return my_dict

def dummy_function_5():
    text = "some benign string"
    if "benign" in text:
        return True
    return False

# ==============================================================================
# Основная логика выполнения модуля
# ==============================================================================

if __name__ == "__main__":
    # Инициализация менеджеров
    db_manager = DatabaseManager()
    api_integrator = ApiServiceIntegrator()

    # 1. Работа с базами данных
    logging.info("--- Начало работы с БД ---")
    mysql_conn = db_manager.get_mysql_connection()
    logging.info(f"Строка подключения MySQL: {mysql_conn}")
    db_manager.connect_to_postgres()
    db_manager.perform_backup("PostgreSQL")
    logging.info("--- Завершение работы с БД ---\n")

    # 2. Работа с API
    logging.info("--- Начало работы с API ---")
    api_integrator.send_payment_request(100.50)
    repos = api_integrator.list_github_repos()
    logging.info(f"Получены репозитории: {[r['name'] for r in repos]}")
    api_integrator.upload_to_s3("/path/to/my/file.zip")
    logging.info("--- Завершение работы с API ---\n")

    # 3. Генерация отчета
    final_report = generate_report(repos)
    logging.info("Итоговый отчет:")
    print(final_report)

    # 4. Дополнительные вызовы для объема
    dummy_function_1()
    dummy_function_2(5, 10)
    dummy_function_3()
    dummy_function_4()
    dummy_function_5()

    # 5. Очистка
    cleanup_logs()

    logging.info("Работа модуля успешно завершена.")
