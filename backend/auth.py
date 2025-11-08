"""
TBGSOSAT CRM - Модуль аутентификации и авторизации
==================================================

Этот файл содержит функции для:
- Хеширования и проверки паролей
- Аутентификации пользователей
- Получения информации о пользователях
- Работы с настройками пользователей

Безопасность:
- Пароли хранятся в виде SHA256 хешей (не в открытом виде)
- Проверка активности аккаунта перед аутентификацией
- Защита от SQL инъекций через параметризованные запросы

Автор: TBGSOSAT Development Team
Версия: 2.0
"""

import hashlib
from database import get_db_connection


def hash_password(password):
    """
    Хеширование пароля с использованием SHA256
    
    Преобразует пароль в хеш для безопасного хранения в базе данных.
    Пароли никогда не хранятся в открытом виде.
    
    Алгоритм: SHA256 (одностороннее хеширование)
    
    Args:
        password (str): Пароль в открытом виде
    
    Returns:
        str: Хеш пароля в шестнадцатеричном формате (64 символа)
    
    Пример:
        hash_password("mypassword123")
        -> "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94"
    
    Примечание:
        SHA256 - это односторонняя функция, нельзя восстановить пароль из хеша.
        Для проверки используется сравнение хешей.
    """
    # Кодируем пароль в байты, хешируем SHA256, преобразуем в hex строку
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, hashed):
    """
    Проверка пароля путем сравнения хешей
    
    Сравнивает хеш введенного пароля с хешем, хранящимся в базе данных.
    
    Args:
        password (str): Пароль для проверки (в открытом виде)
        hashed (str): Хранящийся хеш пароля из базы данных
    
    Returns:
        bool: True если пароли совпадают, False в противном случае
    
    Пример:
        verify_password("mypassword", "ef92b778...") -> True
        verify_password("wrongpass", "ef92b778...") -> False
    """
    # Хешируем введенный пароль и сравниваем с хранящимся хешем
    return hash_password(password) == hashed


def authenticate_user(email, password):
    """
    Аутентификация пользователя по email и паролю
    
    Проверяет существование пользователя, активность аккаунта и правильность пароля.
    Используется при входе в систему.
    
    Процесс:
        1. Поиск пользователя по email в базе данных
        2. Проверка активности аккаунта (is_active = 1)
        3. Проверка правильности пароля
        4. Возврат данных пользователя при успехе
    
    Args:
        email (str): Email адрес пользователя
        password (str): Пароль пользователя
    
    Returns:
        dict: Словарь с данными пользователя при успешной аутентификации
        None: Если пользователь не найден, неактивен или пароль неверен
    
    Пример:
        user = authenticate_user("admin@tbgsosat.com", "admin123")
        if user:
            print(f"Добро пожаловать, {user['username']}!")
    
    Безопасность:
        - Используются параметризованные запросы (защита от SQL инъекций)
        - Проверяется активность аккаунта
        - Пароль проверяется через хеш (не хранится в открытом виде)
    """
    conn = get_db_connection()
    
    # Ищем пользователя по email и проверяем активность
    # Параметризованный запрос защищает от SQL инъекций
    user = conn.execute(
        'SELECT * FROM users WHERE email = ? AND is_active = 1',
        (email,)
    ).fetchone()
    conn.close()

    # Если пользователь найден и пароль верен, возвращаем его данные
    if user and verify_password(password, user['password']):
        # Преобразуем Row объект в словарь для удобства работы
        return dict(user)
    
    # Если аутентификация не удалась, возвращаем None
    return None


def get_user_by_id(user_id):
    """
    Получение информации о пользователе по его ID
    
    Используется для получения данных пользователя из сессии или
    для отображения информации о других пользователях.
    
    Args:
        user_id (int): ID пользователя в базе данных
    
    Returns:
        dict: Словарь с данными пользователя:
            {
                'id': int,
                'username': str,
                'email': str,
                'role': str,
                'is_active': bool,
                'kpi_score': float
            }
        None: Если пользователь не найден
    
    Пример:
        user = get_user_by_id(1)
        if user:
            print(f"Пользователь: {user['username']}, Роль: {user['role']}")
    
    Примечание:
        Не возвращает пароль и другие чувствительные данные для безопасности
    """
    conn = get_db_connection()
    
    # Выбираем только необходимые поля (без пароля)
    user = conn.execute(
        'SELECT id, username, email, role, is_active, kpi_score FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    conn.close()

    # Преобразуем в словарь или возвращаем None
    return dict(user) if user else None


def get_user_settings(user_id):
    """
    Получение настроек пользователя
    
    Возвращает персональные настройки пользователя (тема, уведомления и т.д.)
    
    Args:
        user_id (int): ID пользователя
    
    Returns:
        dict: Словарь с настройками пользователя:
            {
                'id': int,
                'user_id': int,
                'theme': str,  # 'dark' или 'light'
                'colors': str,  # JSON строка с цветами
                'sound_alerts': bool,
                'push_notifications': bool
            }
        None: Если настройки не найдены
    
    Пример:
        settings = get_user_settings(1)
        if settings:
            print(f"Тема: {settings['theme']}")
    """
    conn = get_db_connection()
    
    # Получаем все настройки пользователя
    settings = conn.execute(
        'SELECT * FROM user_settings WHERE user_id = ?',
        (user_id,)
    ).fetchone()
    conn.close()

    # Преобразуем в словарь или возвращаем None
    return dict(settings) if settings else None