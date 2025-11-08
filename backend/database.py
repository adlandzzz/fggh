"""
TBGSOSAT CRM - Модуль работы с базой данных
============================================

Этот файл содержит:
- Функции инициализации базы данных
- Создание всех необходимых таблиц
- Создание индексов для оптимизации производительности
- Добавление тестовых данных
- Функции для получения соединения с БД

База данных: SQLite (tbgsosat_crm.db)
Автор: TBGSOSAT Development Team
Версия: 2.0
"""

import sqlite3
import json
import os
from datetime import datetime
import hashlib


def init_database():
    """
    Инициализация базы данных для CRM системы
    
    Создает все необходимые таблицы, индексы и добавляет тестовые данные.
    Эта функция вызывается при старте приложения и гарантирует, что
    база данных готова к работе.
    
    Процесс инициализации:
    1. Создание таблиц (если не существуют)
    2. Добавление недостающих колонок (миграции)
    3. Создание индексов для оптимизации
    4. Добавление тестовых данных (если БД пустая)
    5. Добавление дефолтных настроек системы
    
    Таблицы:
        - users: Пользователи системы (админы и менеджеры)
        - avito_shops: Магазины на Авито
        - avito_chats: Чаты с клиентами
        - avito_messages: Сообщения в чатах
        - deliveries: Доставки товаров
        - work_schedules: График работы менеджеров
        - И другие...
    
    Returns:
        None (функция не возвращает значение, но выводит статус в консоль)
    """
    # Подключаемся к базе данных SQLite
    # Если файл не существует, он будет создан автоматически
    conn = sqlite3.connect('tbgsosat_crm.db')
    cursor = conn.cursor()

    # ==================== СОЗДАНИЕ ТАБЛИЦ ====================
    
    # Таблица пользователей с ролями
    # Хранит информацию о всех пользователях системы (администраторы и менеджеры)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Уникальный идентификатор пользователя
        username TEXT NOT NULL,                         -- Имя пользователя для отображения
        email TEXT UNIQUE NOT NULL,                     -- Email (уникальный, используется для входа)
        password TEXT NOT NULL,                         -- Хеш пароля (SHA256)
        role TEXT DEFAULT 'manager',                     -- Роль: 'admin' или 'manager'
        is_active BOOLEAN DEFAULT 1,                    -- Активен ли аккаунт (можно деактивировать)
        salary DECIMAL(10,2) DEFAULT 0,                  -- Зарплата менеджера
        kpi_score DECIMAL(5,2) DEFAULT 0,                -- KPI балл (0-100)
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Дата создания аккаунта
        settings TEXT DEFAULT '{}'                      -- JSON строка с настройками пользователя
    )
    ''')

    # Таблица магазинов Авито
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS avito_shops (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        shop_url TEXT UNIQUE NOT NULL,
        api_key TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Таблица назначений менеджеров на магазины
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS manager_assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        manager_id INTEGER,
        shop_id INTEGER,
        assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (manager_id) REFERENCES users (id),
        FOREIGN KEY (shop_id) REFERENCES avito_shops (id)
    )
    ''')

    # Таблица чатов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS avito_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shop_id INTEGER,
        chat_id TEXT UNIQUE NOT NULL,
        client_name TEXT,
        client_phone TEXT,
        product_url TEXT,
        last_message TEXT,
        priority TEXT DEFAULT 'new', -- urgent/new/active/waiting/delivery
        status TEXT DEFAULT 'active',
        unread_count INTEGER DEFAULT 0,
        response_timer INTEGER DEFAULT 0, -- время в минутах
        assigned_manager_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (shop_id) REFERENCES avito_shops (id),
        FOREIGN KEY (assigned_manager_id) REFERENCES users (id)
    )
    ''')

    # Таблица сообщений
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS avito_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER,
        message_text TEXT NOT NULL,
        message_type TEXT DEFAULT 'incoming', -- incoming/outgoing
        sender_name TEXT,
        manager_id INTEGER, -- ID менеджера, отправившего сообщение
        is_read BOOLEAN DEFAULT 0,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (chat_id) REFERENCES avito_chats (id),
        FOREIGN KEY (manager_id) REFERENCES users (id)
    )
    ''')
    
    # Добавляем колонку manager_id если её нет
    try:
        cursor.execute('ALTER TABLE avito_messages ADD COLUMN manager_id INTEGER')
    except:
        pass  # Колонка уже существует

    # Таблица доставок
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER,
        manager_id INTEGER,
        delivery_status TEXT DEFAULT 'in_work', -- in_work/free/closed/on_delivery/refused
        address TEXT,
        tracking_number TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (chat_id) REFERENCES avito_chats (id),
        FOREIGN KEY (manager_id) REFERENCES users (id)
    )
    ''')

    # Таблица KPI настроек
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS kpi_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parameter_name TEXT UNIQUE NOT NULL, -- response_time, conversion, etc
        weight DECIMAL(3,2) DEFAULT 1.0,
        min_value DECIMAL(5,2) DEFAULT 0,
        penalty_amount DECIMAL(10,2) DEFAULT 0,
        bonus_amount DECIMAL(10,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Таблица тем и настроек
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        theme TEXT DEFAULT 'dark', -- dark/light
        colors TEXT DEFAULT '{}',
        sound_alerts BOOLEAN DEFAULT 1,
        push_notifications BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Таблица клиентов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        email TEXT,
        notes TEXT,
        total_orders INTEGER DEFAULT 0,
        total_spent DECIMAL(10,2) DEFAULT 0,
        is_blacklisted BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Таблица тегов клиентов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS client_tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER,
        tag_name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (client_id) REFERENCES clients (id),
        UNIQUE(client_id, tag_name)
    )
    ''')

    # Таблица заказов клиентов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS client_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER,
        chat_id INTEGER,
        order_number TEXT UNIQUE,
        product_name TEXT,
        amount DECIMAL(10,2),
        status TEXT DEFAULT 'pending', -- pending/completed/cancelled
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (client_id) REFERENCES clients (id),
        FOREIGN KEY (chat_id) REFERENCES avito_chats (id)
    )
    ''')

    # Таблица черного списка
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER,
        phone TEXT,
        reason TEXT,
        added_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (client_id) REFERENCES clients (id),
        FOREIGN KEY (added_by) REFERENCES users (id)
    )
    ''')

    # Таблица шаблонов ответов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS message_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT DEFAULT 'general', -- greeting/response/closing/etc
        created_by INTEGER,
        is_active BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id)
    )
    ''')

    # Таблица быстрых ответов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS quick_replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shortcut TEXT UNIQUE NOT NULL, -- например, /привет
        message TEXT NOT NULL,
        created_by INTEGER,
        is_active BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id)
    )
    ''')

    # Таблица настроек системы
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT UNIQUE NOT NULL,
        setting_value TEXT NOT NULL,
        setting_type TEXT DEFAULT 'string', -- string/number/boolean/json
        description TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Таблица автоматизации
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS automation_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        trigger_type TEXT NOT NULL, -- new_chat/time_based/keyword
        trigger_condition TEXT, -- JSON с условиями
        action_type TEXT NOT NULL, -- auto_reply/assign/priority
        action_data TEXT, -- JSON с данными действия
        is_active BOOLEAN DEFAULT 1,
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id)
    )
    ''')

    # Таблица истории KPI
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS kpi_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        period_start DATE,
        period_end DATE,
        response_time_avg DECIMAL(5,2),
        conversion_rate DECIMAL(5,2),
        customer_satisfaction DECIMAL(5,2),
        messages_per_chat DECIMAL(5,2),
        total_score DECIMAL(5,2),
        bonus_amount DECIMAL(10,2) DEFAULT 0,
        penalty_amount DECIMAL(10,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Таблица аналитики
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS analytics_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL, -- message_sent/chat_created/order_created
        user_id INTEGER,
        chat_id INTEGER,
        shop_id INTEGER,
        metadata TEXT, -- JSON с дополнительными данными
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (chat_id) REFERENCES avito_chats (id),
        FOREIGN KEY (shop_id) REFERENCES avito_shops (id)
    )
    ''')

    # Таблица прав доступа ролей
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS role_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role TEXT NOT NULL, -- admin/manager
        permission_key TEXT NOT NULL, -- manage_shops/view_analytics/etc
        is_allowed BOOLEAN DEFAULT 1,
        UNIQUE(role, permission_key)
    )
    ''')

    # Таблица смен (shifts)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS shifts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        manager_id INTEGER NOT NULL,
        shift_date DATE NOT NULL,
        shift_start_time TIMESTAMP,
        shift_end_time TIMESTAMP,
        is_late BOOLEAN DEFAULT 0,
        late_minutes INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active', -- active/completed/cancelled
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (manager_id) REFERENCES users (id),
        UNIQUE(manager_id, shift_date)
    )
    ''')

    # Таблица штрафов (penalties)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS penalties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        manager_id INTEGER NOT NULL,
        shift_id INTEGER,
        penalty_type TEXT NOT NULL, -- late_shift/poor_performance/etc
        penalty_amount DECIMAL(10,2) NOT NULL,
        reason TEXT,
        is_paid BOOLEAN DEFAULT 0,
        created_by INTEGER, -- admin who created penalty
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        paid_at TIMESTAMP,
        FOREIGN KEY (manager_id) REFERENCES users (id),
        FOREIGN KEY (shift_id) REFERENCES shifts (id),
        FOREIGN KEY (created_by) REFERENCES users (id)
    )
    ''')

    # Таблица логов действий (activity_logs)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action_type TEXT NOT NULL, -- login/logout/send_message/open_chat/complete_chat/etc
        action_description TEXT,
        target_type TEXT, -- chat/user/shop/etc
        target_id INTEGER,
        metadata TEXT, -- JSON с дополнительными данными
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    # Таблица графика работы (work_schedules)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS work_schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        day_of_week INTEGER NOT NULL, -- 0=Понедельник, 1=Вторник, ..., 6=Воскресенье
        start_time TIME NOT NULL, -- Время начала работы (например, 09:00)
        end_time TIME NOT NULL, -- Время окончания работы (например, 18:00)
        is_working_day BOOLEAN DEFAULT 1, -- Рабочий день или выходной
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(user_id, day_of_week)
    )
    ''')

    # Таблица назначения менеджеров на дни недели (для общего графика)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS day_manager_assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        day_of_week INTEGER NOT NULL, -- 0=Понедельник, 1=Вторник, ..., 6=Воскресенье
        manager_id INTEGER NOT NULL,
        start_time TIME, -- Время начала работы (например, 09:00)
        end_time TIME, -- Время окончания работы (например, 18:00)
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (manager_id) REFERENCES users (id),
        UNIQUE(day_of_week, manager_id)
    )
    ''')

    # Добавляем тестовые данные
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Хешируем пароли
        def hash_password(password):
            return hashlib.sha256(password.encode()).hexdigest()

        # Добавляем администратора
        cursor.execute('''
        INSERT INTO users (username, email, password, role, salary, settings)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            'Администратор',
            'admin@tbgsosat.com',
            hash_password('admin123'),
            'admin',
            0,
            json.dumps({'theme': 'dark', 'notifications': True})
        ))

        # Добавляем менеджера
        cursor.execute('''
        INSERT INTO users (username, email, password, role, salary, kpi_score, settings)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            'Адлан Джабраилов',
            'dannnnnbb@gmail.com',
            hash_password('manager123'),
            'manager',
            50000,
            85.5,
            json.dumps({'theme': 'dark', 'sound_alerts': True})
        ))

        # Добавляем тестовые магазины
        cursor.execute('''
        INSERT INTO avito_shops (name, shop_url, api_key)
        VALUES (?, ?, ?)
        ''', ('Магазин электроники', 'https://www.avito.ru/user123', 'test_api_key_1'))

        cursor.execute('''
        INSERT INTO avito_shops (name, shop_url, api_key) 
        VALUES (?, ?, ?)
        ''', ('Магазин одежды', 'https://www.avito.ru/user456', 'test_api_key_2'))

        # Назначаем менеджера на магазины
        cursor.execute('''
        INSERT INTO manager_assignments (manager_id, shop_id)
        VALUES (?, ?)
        ''', (2, 1))

        cursor.execute('''
        INSERT INTO manager_assignments (manager_id, shop_id)
        VALUES (?, ?)
        ''', (2, 2))

        # Добавляем KPI настройки
        kpi_parameters = [
            ('response_time', 0.3, 10, 500, 1000),
            ('conversion_rate', 0.4, 20, 300, 800),
            ('customer_satisfaction', 0.2, 80, 200, 500),
            ('messages_per_chat', 0.1, 5, 100, 300)
        ]

        for param in kpi_parameters:
            cursor.execute('''
            INSERT INTO kpi_settings (parameter_name, weight, min_value, penalty_amount, bonus_amount)
            VALUES (?, ?, ?, ?, ?)
            ''', param)

        # Добавляем настройки пользователей
        cursor.execute('INSERT INTO user_settings (user_id) VALUES (?)', (1,))
        cursor.execute('INSERT INTO user_settings (user_id) VALUES (?)', (2,))

        # Добавляем дефолтные настройки системы
        default_settings = [
            ('timer_new_chat_hours', '1', 'number', 'Время для "нового" чата (часы)'),
            ('timer_urgent_minutes', '20', 'number', 'Время для "срочного" чата (минуты)'),
            ('timer_critical_minutes', '60', 'number', 'Критическое время ответа (минуты)'),
            ('notification_blink_interval', '1000', 'number', 'Интервал мигания уведомлений (мс)'),
            ('color_urgent', '#ef4444', 'string', 'Цвет для срочных чатов'),
            ('color_new', '#f59e0b', 'string', 'Цвет для новых чатов'),
            ('color_active', '#10b981', 'string', 'Цвет для активных чатов'),
            ('color_delivery', '#8b5cf6', 'string', 'Цвет для доставок'),
            ('sound_enabled', 'true', 'boolean', 'Включить звуковые уведомления'),
            ('push_enabled', 'true', 'boolean', 'Включить push-уведомления'),
            ('email_enabled', 'false', 'boolean', 'Включить email оповещения'),
            ('telegram_enabled', 'false', 'boolean', 'Включить Telegram бот'),
        ]

        for setting in default_settings:
            cursor.execute('''
                INSERT OR IGNORE INTO system_settings (setting_key, setting_value, setting_type, description)
                VALUES (?, ?, ?, ?)
            ''', setting)

        # Добавляем права доступа для ролей
        admin_permissions = [
            ('admin', 'manage_users', 1),
            ('admin', 'manage_shops', 1),
            ('admin', 'manage_settings', 1),
            ('admin', 'view_analytics', 1),
            ('admin', 'manage_kpi', 1),
            ('admin', 'manage_automation', 1),
            ('admin', 'view_all_chats', 1),
            ('admin', 'manage_clients', 1),
        ]

        manager_permissions = [
            ('manager', 'view_own_chats', 1),
            ('manager', 'send_messages', 1),
            ('manager', 'view_own_analytics', 1),
            ('manager', 'use_templates', 1),
            ('manager', 'manage_deliveries', 1),
        ]

        for perm in admin_permissions + manager_permissions:
            cursor.execute('''
                INSERT OR IGNORE INTO role_permissions (role, permission_key, is_allowed)
                VALUES (?, ?, ?)
            ''', perm)

        # Добавляем дефолтные шаблоны ответов
        default_templates = [
            ('Приветствие', 'Здравствуйте! Спасибо за интерес к нашему товару. Чем могу помочь?', 'greeting', 1),
            ('Уточнение наличия', 'Да, товар в наличии. Могу ответить на ваши вопросы.', 'response', 1),
            ('Прощание', 'Спасибо за обращение! Если возникнут вопросы, обращайтесь.', 'closing', 1),
        ]

        for template in default_templates:
            cursor.execute('''
                INSERT INTO message_templates (name, content, category, created_by)
                VALUES (?, ?, ?, ?)
            ''', template)

        # Добавляем дефолтные быстрые ответы
        default_quick_replies = [
            ('/привет', 'Здравствуйте! Чем могу помочь?', 1),
            ('/наличие', 'Да, товар в наличии. Могу ответить на ваши вопросы.', 1),
            ('/цена', 'Цена актуальна. Могу предоставить дополнительную информацию.', 1),
        ]

        for reply in default_quick_replies:
            cursor.execute('''
                INSERT INTO quick_replies (shortcut, message, created_by)
                VALUES (?, ?, ?)
            ''', reply)

        # Добавляем тестовые чаты для демонстрации
        test_chats = [
            # СРОЧНЫЕ чаты (>20 минут)
            (1, 'chat_001', 'Иван Петров', '+79161234567', 'https://www.avito.ru/iphone',
             'Здравствуйте! Интересует iPhone 13. Есть в наличии?', 'urgent', 'active', 1, 25, 2),
            (1, 'chat_002', 'Мария Сидорова', '+79167654321', 'https://www.avito.ru/macbook',
             'Срочно нужен MacBook Pro! Цена актуальна?', 'urgent', 'active', 2, 35, 2),

            # НОВЫЕ чаты (<1 часа)
            (2, 'chat_003', 'Алексей Козлов', '+79169998877', 'https://www.avito.ru/jacket',
             'Добрый день! Какой размер посоветуете?', 'new', 'active', 0, 5, 2),
            (1, 'chat_004', 'Елена Васнецова', '+79165554433', 'https://www.avito.ru/airpods',
             'Здравствуйте! AirPods Pro есть в наличии?', 'new', 'active', 0, 15, 2),

            # АКТИВНЫЕ чаты
            (2, 'chat_005', 'Дмитрий Орлов', '+79162223344', 'https://www.avito.ru/shoes', 'Спасибо! Жду доставку',
             'active', 'active', 0, 120, 2),
            (1, 'chat_006', 'Ольга Новикова', '+79163332211', 'https://www.avito.ru/watch', 'Уточните гарантию',
             'active', 'active', 1, 180, 2),

            # ЧАТЫ В ДОСТАВКЕ
            (2, 'chat_007', 'Сергей Волков', '+79164445566', 'https://www.avito.ru/dress', 'Заказ получен, спасибо!',
             'delivery', 'completed', 0, 300, 2),
            (1, 'chat_008', 'Анна Морозова', '+79167778899', 'https://www.avito.ru/camera', 'Когда будет доставка?',
             'delivery', 'processing', 0, 250, 2),
        ]

        for chat in test_chats:
            cursor.execute('''
            INSERT INTO avito_chats (shop_id, chat_id, client_name, client_phone, product_url, last_message, priority, status, unread_count, response_timer, assigned_manager_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', chat)

        # Добавляем тестовые сообщения
        test_messages = [
            (1, 'Здравствуйте! Интересует iPhone 13. Есть в наличии?', 'incoming', 'Иван Петров', 0),
            (2, 'Срочно нужен MacBook Pro! Цена актуальна?', 'incoming', 'Мария Сидорова', 0),
            (3, 'Добрый день! Какой размер посоветуете?', 'incoming', 'Алексей Козлов', 0),
            (4, 'Здравствуйте! AirPods Pro есть в наличии?', 'incoming', 'Елена Васнецова', 0),
            (5, 'Спасибо! Жду доставку', 'incoming', 'Дмитрий Орлов', 1),
            (6, 'Уточните гарантию', 'incoming', 'Ольга Новикова', 0),
            (7, 'Заказ получен, спасибо!', 'incoming', 'Сергей Волков', 1),
            (8, 'Когда будет доставка?', 'incoming', 'Анна Морозова', 0),
        ]

        for msg in test_messages:
            cursor.execute('''
            INSERT INTO avito_messages (chat_id, message_text, message_type, sender_name, is_read)
            VALUES (?, ?, ?, ?, ?)
            ''', msg)

        print("[OK] Тестовые чаты и сообщения добавлены")

    # Создаем индексы для оптимизации производительности
    indexes = [
        # Индексы для таблицы доставок
        "CREATE INDEX IF NOT EXISTS idx_deliveries_manager_id ON deliveries(manager_id)",
        "CREATE INDEX IF NOT EXISTS idx_deliveries_chat_id ON deliveries(chat_id)",
        "CREATE INDEX IF NOT EXISTS idx_deliveries_status ON deliveries(delivery_status)",
        "CREATE INDEX IF NOT EXISTS idx_deliveries_updated_at ON deliveries(updated_at DESC)",
        
        # Индексы для таблицы чатов
        "CREATE INDEX IF NOT EXISTS idx_chats_shop_id ON avito_chats(shop_id)",
        "CREATE INDEX IF NOT EXISTS idx_chats_manager_id ON avito_chats(assigned_manager_id)",
        "CREATE INDEX IF NOT EXISTS idx_chats_status ON avito_chats(status)",
        "CREATE INDEX IF NOT EXISTS idx_chats_priority ON avito_chats(priority)",
        "CREATE INDEX IF NOT EXISTS idx_chats_updated_at ON avito_chats(updated_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_chats_client_phone ON avito_chats(client_phone)",
        
        # Индексы для таблицы сообщений
        "CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON avito_messages(chat_id)",
        "CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON avito_messages(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_messages_manager_id ON avito_messages(manager_id)",
        
        # Индексы для таблицы назначений менеджеров
        "CREATE INDEX IF NOT EXISTS idx_manager_assignments_manager_id ON manager_assignments(manager_id)",
        "CREATE INDEX IF NOT EXISTS idx_manager_assignments_shop_id ON manager_assignments(shop_id)",
        
        # Индексы для графика работы
        "CREATE INDEX IF NOT EXISTS idx_work_schedules_user_id ON work_schedules(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_work_schedules_day ON work_schedules(day_of_week)",
        "CREATE INDEX IF NOT EXISTS idx_day_managers_day ON day_manager_assignments(day_of_week)",
        "CREATE INDEX IF NOT EXISTS idx_day_managers_manager ON day_manager_assignments(manager_id)",
        
        # Индексы для аналитики
        "CREATE INDEX IF NOT EXISTS idx_analytics_user_id ON analytics_logs(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_analytics_created_at ON analytics_logs(created_at DESC)",
        
        # Индексы для активности
        "CREATE INDEX IF NOT EXISTS idx_activity_user_id ON activity_logs(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_activity_created_at ON activity_logs(created_at DESC)",
    ]
    
    for index_sql in indexes:
        try:
            cursor.execute(index_sql)
        except Exception as e:
            print(f"[WARNING] Не удалось создать индекс: {e}")
    
    conn.commit()
    conn.close()
    print("[OK] CRM база данных инициализирована с индексами")


def get_db_connection():
    """
    Получение соединения с базой данных
    
    Создает новое соединение с SQLite базой данных и настраивает его
    для удобной работы с результатами запросов.
    
    Настройки:
        - row_factory = sqlite3.Row: Позволяет обращаться к колонкам по имени
          (например: row['username'] вместо row[1])
    
    Важно:
        - Каждый вызов создает новое соединение
        - Необходимо закрывать соединение после использования (conn.close())
        - Рекомендуется использовать try/finally для гарантированного закрытия
    
    Returns:
        sqlite3.Connection: Объект соединения с базой данных
    
    Пример использования:
        conn = get_db_connection()
        try:
            users = conn.execute('SELECT * FROM users').fetchall()
            # Работа с данными
        finally:
            conn.close()
    """
    # Подключаемся к базе данных
    conn = sqlite3.connect('tbgsosat_crm.db')
    
    # Устанавливаем row_factory для доступа к колонкам по имени
    # Это позволяет использовать row['column_name'] вместо row[0]
    conn.row_factory = sqlite3.Row
    
    return conn


# Инициализируем базу данных при импорте
init_database()