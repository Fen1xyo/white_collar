# secret-scanner/scanner/rules/rule_loader.py

import yaml
from typing import List
from dataclasses import dataclass

@dataclass
class Rule:
    """
    Датакласс для представления одного правила сканирования.
    Определяет, что и как искать.
    """
    id: str
    name: str
    pattern: str
    severity: str
    description: str
    remediation: str

class RuleLoader:
    """
    Отвечает за загрузку и валидацию правил сканирования из списка YAML-файлов.
    """
    def __init__(self, rule_paths: List[str]):
        if not isinstance(rule_paths, list):
            raise TypeError("rule_paths должен быть списком путей к файлам.")
        self.rule_paths = rule_paths

    def load_rules(self) -> List[Rule]:
        """
        Загружает правила из всех указанных YAML-файлов.
        Пропускает файлы, которые не удалось найти или распарсить.
        """
        all_rules: List[Rule] = []
        print(f"Загрузка правил из: {self.rule_paths}")

        for path in self.rule_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    
                    if not data or 'rules' not in data:
                        print(f"Предупреждение: В файле {path} отсутствует обязательный ключ 'rules'. Файл пропущен.")
                        continue
                    
                    if not isinstance(data['rules'], list):
                        print(f"Предупреждение: Ключ 'rules' в файле {path} должен содержать список. Файл пропущен.")
                        continue

                    for i, rule_data in enumerate(data['rules']):
                        try:
                            # Создаем объект Rule, передавая словарь с данными
                            # Если в rule_data не хватает полей, dataclass вызовет TypeError
                            rule = Rule(**rule_data)
                            all_rules.append(rule)
                        except TypeError as e:
                            print(f"Предупреждение: Некорректный формат правила #{i+1} в файле {path}. {e}. Правило пропущено.")
                        except Exception as e:
                            print(f"Предупреждение: Неизвестная ошибка при обработке правила #{i+1} в {path}: {e}. Правило пропущено.")

            except FileNotFoundError:
                print(f"Ошибка: Файл с правилами не найден: {path}. Файл пропущен.")
            except yaml.YAMLError as e:
                print(f"Ошибка: Некорректный синтаксис YAML в файле {path}: {e}. Файл пропущен.")
            except Exception as e:
                print(f"Ошибка: Не удалось прочитать файл с правилами {path}: {e}. Файл пропущен.")
        
        print(f"Успешно загружено правил: {len(all_rules)}.")
        return all_rules
