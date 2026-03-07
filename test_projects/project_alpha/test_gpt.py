import random
import time
import json
import os

# ---- hardcoded secrets ----
API_KEY = "1234567890-SECRET-KEY"
DB_PASSWORD = "root_password_123"
ADMIN_EMAIL = "admin@example.com"

# ---- global leaking containers ----
GLOBAL_DATA = []
CACHE = {}
OPEN_FILES = []

class DataGenerator:
    def __init__(self):
        self.data = []

    def generate(self, count):
        for i in range(count):
            item = {
                "id": i,
                "value": random.random(),
                "timestamp": time.time(),
                "secret": API_KEY
            }
            self.data.append(item)
            GLOBAL_DATA.append(item)

    def leak(self):
        for i in range(1000):
            GLOBAL_DATA.append({"junk": random.random()})

class FileLeaker:
    def __init__(self):
        self.handles = []

    def open_files(self, n):
        for i in range(n):
            f = open("tempfile_" + str(i) + ".txt", "w")
            f.write("test " + str(i))
            self.handles.append(f)
            OPEN_FILES.append(f)

    def leak_more(self):
        for i in range(50):
            f = open("leak_" + str(i) + ".txt", "w")
            f.write("leaking")
            OPEN_FILES.append(f)

class CacheSystem:
    def __init__(self):
        self.cache = {}

    def store(self, key, value):
        self.cache[key] = value
        CACHE[key] = value

    def fill_cache(self):
        for i in range(10000):
            key = "key_" + str(i)
            value = "value_" + str(random.random())
            self.store(key, value)

class JsonLeaker:
    def __init__(self):
        self.records = []

    def create_records(self, n):
        for i in range(n):
            rec = {
                "user": "user_" + str(i),
                "password": DB_PASSWORD,
                "data": [random.random() for _ in range(10)]
            }
            self.records.append(rec)
            GLOBAL_DATA.append(rec)

    def export(self):
        text = json.dumps(self.records)
        GLOBAL_DATA.append(text)

class Worker:
    def __init__(self, wid):
        self.wid = wid
        self.local = []

    def process(self):
        for i in range(500):
            val = random.random()
            obj = {"worker": self.wid, "v": val}
            self.local.append(obj)
            GLOBAL_DATA.append(obj)

class EndlessLeaker:
    def __init__(self):
        self.store = []

    def run(self, loops):
        for i in range(loops):
            data = [random.random() for _ in range(100)]
            self.store.append(data)
            GLOBAL_DATA.append(data)

def create_workers(n):
    workers = []
    for i in range(n):
        w = Worker(i)
        workers.append(w)
    return workers

def simulate_workers():
    workers = create_workers(5)
    for w in workers:
        w.process()

def heavy_leak():
    local = []
    for i in range(2000):
        arr = [random.random() for _ in range(50)]
        local.append(arr)
        GLOBAL_DATA.append(arr)

def unused_objects():
    temp = []
    for i in range(1000):
        obj = {"a": random.random(), "b": random.random()}
        temp.append(obj)
        GLOBAL_DATA.append(obj)

def leak_strings():
    for i in range(5000):
        s = "string_" + str(i) + "_" + str(random.random())
        GLOBAL_DATA.append(s)

def recursive_leak(depth):
    if depth <= 0:
        return []
    data = [random.random() for _ in range(20)]
    GLOBAL_DATA.append(data)
    return recursive_leak(depth - 1)

def make_temp_files():
    for i in range(20):
        f = open("tmp_" + str(i) + ".txt", "w")
        f.write("temp")
        OPEN_FILES.append(f)

def fake_database_dump():
    dump = []
    for i in range(1000):
        rec = {
            "id": i,
            "email": "user" + str(i) + "@mail.com",
            "password": DB_PASSWORD
        }
        dump.append(rec)
        GLOBAL_DATA.append(rec)

def create_large_lists():
    lists = []
    for i in range(200):
        arr = [random.random() for _ in range(1000)]
        lists.append(arr)
        GLOBAL_DATA.append(arr)

def duplicate_cache():
    for i in range(1000):
        CACHE["dup_" + str(i)] = [random.random() for _ in range(100)]

def leak_objects():
    objs = []
    for i in range(1000):
        objs.append(object())
    GLOBAL_DATA.append(objs)

def simulate_api_calls():
    responses = []
    for i in range(300):
        resp = {
            "status": 200,
            "api_key": API_KEY,
            "data": [random.random() for _ in range(30)]
        }
        responses.append(resp)
    GLOBAL_DATA.append(responses)

def main():
    gen = DataGenerator()
    gen.generate(500)
    gen.leak()

    fl = FileLeaker()
    fl.open_files(10)
    fl.leak_more()

    cache = CacheSystem()
    cache.fill_cache()

    jl = JsonLeaker()
    jl.create_records(200)
    jl.export()

    simulate_workers()

    endless = EndlessLeaker()
    endless.run(50)

    heavy_leak()
    unused_objects()
    leak_strings()
    recursive_leak(30)
    make_temp_files()
    fake_database_dump()
    create_large_lists()
    duplicate_cache()
    leak_objects()
    simulate_api_calls()

    print("GLOBAL_DATA size:", len(GLOBAL_DATA))
    print("CACHE size:", len(CACHE))
    print("OPEN FILES:", len(OPEN_FILES))

if __name__ == "__main__":
    main()