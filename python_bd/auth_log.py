import psycopg2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import getpass  # Чтобы пароль не отображался при вводе

# Настройки подключения
DB_HOST = 'localhost'
DB_NAME = 'testdb'
DB_USER = 'postgres'
DB_PASSWORD = getpass.getpass("Введите пароль БД: ").strip()

# Инициализация Argon2
ph = PasswordHasher(time_cost=3, memory_cost=64_000, parallelism=2, hash_len=32, salt_len=16)

# Создание таблицы пользователей
def create_table():
    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

# Регистрация пользователя
def register_user(username, password):
    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    password_hash = ph.hash(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        conn.commit()
        print(f"Пользователь '{username}' успешно зарегистрирован.")
    except psycopg2.errors.UniqueViolation:
        print("Пользователь с таким именем уже существует.")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

# Аутентификация пользователя
def authenticate_user(username, password):
    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
    result = cur.fetchone()
    if result:
        stored_hash = result[0]
        try:
            ph.verify(stored_hash, password)
            print("Аутентификация успешна!")
            success = True
        except VerifyMismatchError:
            print("Неверный пароль.")
            success = False
    else:
        print("Пользователь не найден.")
        success = False
    cur.close()
    conn.close()
    return success

# Главное меню
def main():
    create_table()  # Проверяем/создаём таблицу

    while True:
        print("\nВыберите действие:")
        print("1 - Регистрация")
        print("2 - Вход")
        print("3 - Выход из программы")
        choice = input("Введите 1, 2 или 3: ").strip()

        if choice == "1":
            username = input("Введите логин: ").strip()
            password = getpass.getpass("Введите пароль: ").strip()
            register_user(username, password)
        elif choice == "2":
            username = input("Введите логин: ").strip()
            password = getpass.getpass("Введите пароль: ").strip()
            authenticate_user(username, password)
        elif choice == "3":
            print("Выход из программы.")
            break
        else:
            print("Некорректный выбор. Попробуйте снова.")

if __name__ == "__main__":
    main()
