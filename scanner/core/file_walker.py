# secret-scanner/scanner/core/file_walker.py

import os
# ИСПРАВЛЕНО: Добавлен 'Tuple' в импорты из typing
from typing import List, Generator, Optional, Set, Tuple
import git

class FileWalker:
    """ Класс для обхода файловой системы и истории Git. Отвечает на вопрос "Какие файлы и какое их содержимое мы должны сканировать?". """
    def __init__(self, project_path: str, exclude_dirs: List[str], scan_extensions: List[str]):
        self.project_path = os.path.abspath(project_path)
        self.exclude_dirs: Set[str] = set(exclude_dirs)
        self.scan_extensions: Set[str] = set(scan_extensions)

    def _should_scan_file(self, filename: str) -> bool:
        """ Внутренний метод для проверки, нужно ли сканировать файл. """
        basename = os.path.basename(filename).lower()
        ext = os.path.splitext(filename)[1].lower()
        return basename in self.scan_extensions or ext in self.scan_extensions

    def walk_files(self) -> Generator[str, None, None]:
        """ Обходит директорию проекта и возвращает пути к файлам для сканирования. """
        for root, dirs, files in os.walk(self.project_path, topdown=True):
            # Исключаем нежелательные директории из дальнейшего обхода
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for file in files:
                if self._should_scan_file(file):
                    full_path = os.path.join(root, file)
                    yield full_path

    def scan_git_history(self) -> Generator[Tuple[str, str, str], None, None]:
        """ Сканирует всю историю Git, возвращая содержимое каждого файла (blob) в каждом коммите. """
        try:
            repo = git.Repo(self.project_path)
            if repo.bare:
                print(f"Предупреждение: Репозиторий {self.project_path} является 'bare', сканирование истории может быть неполным.")
                return
        except git.InvalidGitRepositoryError:
            print(f"Ошибка: Директория {self.project_path} не является Git-репозиторием. Сканирование истории Git невозможно.")
            return
        except git.NoSuchPathError:
            print(f"Ошибка: Путь к репозиторию {self.project_path} не найден.")
            return

        all_commits = list(repo.iter_commits('--all'))
        scanned_blobs: Set[str] = set()

        for commit in all_commits:
            try:
                # Рекурсивно обходим все файлы в дереве коммита
                for blob in commit.tree.traverse():
                    if blob.type == 'blob' and blob.hexsha not in scanned_blobs:
                        if self._should_scan_file(blob.path):
                            scanned_blobs.add(blob.hexsha)
                            try:
                                # Декодируем содержимое файла, пропуская ошибки
                                content = blob.data_stream.read().decode('utf-8', errors='replace')
                                yield content, blob.path, commit.hexsha
                            except Exception:
                                # Пропускаем бинарные или поврежденные файлы
                                continue
            except Exception as e:
                print(f"Предупреждение: Не удалось полностью обработать коммит {commit.hexsha[:7]}: {e}")
                continue
