# test_projects/project_alpha/data_processing_pipeline.py

import pandas as pd
import numpy as np
import requests
import time
from multiprocessing import Pool

# ==============================================================================
# Константы и конфигурация
# ==============================================================================

# Токен для бота в Telegram.
# ИСПРАВЛЕНО: было 31 символ после "AA" — не хватало 2 символов до минимума паттерна {33}.
# Теперь ровно 33 символа: AAG-AbcDef1234567890GhiJkl-MnoPqrSt
TELEGRAM_BOT_TOKEN = "1234567890:AAG-AbcDef1234567890GhiJkl-MnoPqrSt"

# IAM-токен Yandex Cloud.
# Паттерн теперь допускает точки внутри токена (t1\.[A-Za-z0-9_\-\.]{150,}),
# поэтому этот токен будет найден без изменений.
YANDEX_IAM_TOKEN = "t1.9euelZqPj56LmcaPk56OkZOLkZGLm-3rnpWaj5bHlZCOj5rPlY6NnZCLk5fl8_t9G09R-e9YF0Zg_t3z931RTfnvWBdGYA.a-b_cDefGHIjklmnoPQRstuvwxYZ1234567890ABCdefghiJKLMnopqrstuvWXYZabcdefghijKLMNOpqrstuvwxyz123456789"

# Приватный ключ для доступа к SFTP-серверу
SSH_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqK5d... (много данных ключа) ...
... (много данных ключа) ...
... (много данных ключа) ...
-----END RSA PRIVATE KEY-----
"""

# URL для внутреннего API
INTERNAL_API_URL = "http://192.168.1.100/api/v2/data"

# ==============================================================================
# Функции извлечения данных (Extract)
# ==============================================================================

def fetch_data_from_source_db():
    """Имитация загрузки данных из основной БД."""
    print("Извлечение данных из источника...")
    time.sleep(2)
    data = {
        'user_id': np.arange(1, 101),
        'metric_1': np.random.rand(100) * 1000,
        'metric_2': np.random.randint(0, 5, 100),
        'category': np.random.choice(['A', 'B', 'C', 'D'], 100)
    }
    df = pd.DataFrame(data)
    print(f"Извлечено {len(df)} строк.")
    return df


def fetch_data_from_internal_api():
    """Загрузка данных из внутреннего API."""
    print(f"Запрос данных из {INTERNAL_API_URL}")
    try:
        headers = {"X-Auth-Token": "generic_token_value_for_internal_api_12345"}
        response = requests.get(INTERNAL_API_URL, headers=headers, timeout=5)
        response.raise_for_status()
        print("Данные из API успешно получены.")
        return pd.DataFrame(response.json())
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при запросе к API: {e}")
        return pd.DataFrame()


# ==============================================================================
# Функции преобразования данных (Transform)
# ==============================================================================

def clean_data(df):
    """Очистка и предварительная обработка данных."""
    print("Начало очистки данных...")
    df.dropna(inplace=True)
    df['metric_1'] = df['metric_1'].astype(int)
    df['user_id'] = df['user_id'].astype(str)
    print("Данные очищены.")
    return df


def enrich_data(df):
    """Обогащение данных."""
    print("Обогащение данных...")
    df['metric_sum'] = df['metric_1'] + df['metric_2']
    df['category_encoded'] = df['category'].astype('category').cat.codes

    def complex_calc(row):
        if row['category'] == 'A':
            return row['metric_sum'] * 1.1
        elif row['category'] == 'B':
            return row['metric_sum'] * 1.2
        else:
            return row['metric_sum']

    df['enriched_metric'] = df.apply(complex_calc, axis=1)
    print("Данные обогащены.")
    return df


def process_chunk(df_chunk):
    """Обработка одного чанка данных в параллельном режиме."""
    cleaned_df = clean_data(df_chunk)
    enriched_df = enrich_data(cleaned_df)
    return enriched_df


# ==============================================================================
# Функции загрузки данных (Load)
# ==============================================================================

def load_data_to_dwh(df):
    """Загрузка данных в хранилище (DWH)."""
    print("Загрузка данных в DWH...")
    if YANDEX_IAM_TOKEN.startswith("t1."):
        print("Аутентификация в Yandex Cloud с использованием IAM-токена.")
        time.sleep(3)
        print(f"Успешно загружено {len(df)} строк в DWH.")
    else:
        print("Ошибка: неверный формат IAM-токена Yandex Cloud.")


def send_telegram_notification(message):
    """Отправка уведомления в Telegram."""
    print("Отправка уведомления в Telegram...")
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    params = {'chat_id': '@my_channel', 'text': message}
    try:
        response = requests.post(url, params=params)
        if response.status_code == 200:
            print("Уведомление успешно отправлено.")
        else:
            print(f"Ошибка отправки уведомления: {response.text}")
    except Exception as e:
        print(f"Критическая ошибка при отправке в Telegram: {e}")


# ==============================================================================
# Основной пайплайн
# ==============================================================================

def run_pipeline():
    """Запускает полный ETL-пайплайн."""
    import os
    start_time = time.time()
    print("=" * 50)
    print("ЗАПУСК ETL-ПАЙПЛАЙНА")
    print("=" * 50)

    # 1. Extract
    source_df = fetch_data_from_source_db()
    api_df = fetch_data_from_internal_api()
    if api_df.empty:
        print("Пропускаем объединение с данными API.")
        main_df = source_df
    else:
        main_df = pd.merge(source_df, api_df, on='user_id', how='left')

    # 2. Transform (в параллельном режиме)
    print("Начало параллельной обработки данных...")
    num_processes = os.cpu_count() or 1
    chunks = np.array_split(main_df, num_processes)
    with Pool(num_processes) as pool:
        processed_chunks = pool.map(process_chunk, chunks)
    final_df = pd.concat(processed_chunks)
    print("Параллельная обработка завершена.")

    # 3. Load
    load_data_to_dwh(final_df)

    # 4. Notification
    end_time = time.time()
    duration = end_time - start_time
    message = f"ETL-пайплайн успешно завершен за {duration:.2f} секунд. Обработано {len(final_df)} строк."
    send_telegram_notification(message)

    print("=" * 50)
    print("ETL-ПАЙПЛАЙН ЗАВЕРШЕН")
    print("=" * 50)


# ==============================================================================
# Вспомогательные функции
# ==============================================================================

def helper_func_1():
    for _ in range(10):
        pass
    return True

def helper_func_2():
    my_set = {i for i in range(200)}
    return len(my_set)

def helper_func_3():
    data = "a,b,c,d,e,f,g"
    return data.split(',')

def helper_func_4():
    return all([True, True, True, not False])

def helper_func_5():
    return any([False, False, True, False])

def helper_func_6():
    return list(map(lambda x: x*x, range(10)))

def helper_func_7():
    from functools import reduce
    return reduce(lambda x, y: x+y, range(10))

def helper_func_8():
    return "this is just a test string, not a secret"

def helper_func_9():
    return 123456789

def helper_func_10():
    return 3.1415926535


if __name__ == "__main__":
    run_pipeline()
    helper_func_1()
    helper_func_2()
    helper_func_3()
    helper_func_4()
    helper_func_5()
    helper_func_6()
    helper_func_7()
    helper_func_8()
    helper_func_9()
    helper_func_10()