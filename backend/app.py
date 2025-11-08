"""
TBGSOSAT CRM - Основной файл приложения Flask
==============================================

Этот файл содержит:
- Инициализацию Flask приложения
- API endpoints для работы с данными
- Маршруты для отображения страниц
- Декораторы для безопасности и обработки ошибок
- Утилиты для валидации и логирования

Автор: TBGSOSAT Development Team
Версия: 2.0
"""

from flask import Flask, jsonify, render_template, send_from_directory, request, session, redirect, url_for
from flask_cors import CORS
from functools import wraps, lru_cache
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from database import get_db_connection, init_database
from auth import authenticate_user, get_user_by_id, get_user_settings
import time

# ==================== ИНИЦИАЛИЗАЦИЯ ПРИЛОЖЕНИЯ ====================

# Создаем экземпляр Flask приложения
# __name__ используется для определения корневой директории проекта
app = Flask(__name__)

# Устанавливаем секретный ключ для сессий
# Используется для шифрования данных сессии (cookies)
# Если переменная окружения SECRET_KEY не установлена, генерируется случайный ключ
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Включаем CORS (Cross-Origin Resource Sharing) для работы с фронтендом
# supports_credentials=True позволяет передавать cookies между доменами
CORS(app, supports_credentials=True)

# Инициализируем базу данных при старте приложения
# Создает все необходимые таблицы, индексы и тестовые данные
init_database()

# ==================== УТИЛИТЫ И ВАЛИДАЦИЯ ====================

def validate_email(email):
    """
    Валидация email адреса
    
    Проверяет корректность формата email с помощью регулярного выражения.
    Поддерживает стандартный формат: user@domain.com
    
    Args:
        email (str): Email адрес для проверки
    
    Returns:
        bool: True если email валиден, False в противном случае
    
    Примеры:
        validate_email("user@example.com") -> True
        validate_email("invalid.email") -> False
    """
    # Регулярное выражение для проверки формата email
    # ^ - начало строки
    # [a-zA-Z0-9._%+-]+ - имя пользователя (один или более символов)
    # @ - символ @
    # [a-zA-Z0-9.-]+ - доменное имя
    # \. - точка перед доменом верхнего уровня
    # [a-zA-Z]{2,} - домен верхнего уровня (минимум 2 буквы)
    # $ - конец строки
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """
    Валидация номера телефона
    
    Проверяет корректность формата международного номера телефона.
    Удаляет пробелы и дефисы перед проверкой.
    
    Args:
        phone (str): Номер телефона для проверки
    
    Returns:
        bool: True если номер валиден, False в противном случае
    
    Примеры:
        validate_phone("+79161234567") -> True
        validate_phone("7916-123-45-67") -> True (после удаления дефисов)
        validate_phone("123") -> False
    """
    # Удаляем пробелы и дефисы для унификации формата
    cleaned_phone = phone.replace(' ', '').replace('-', '')
    
    # Регулярное выражение для международного формата:
    # ^\+? - необязательный знак + в начале
    # [1-9] - первая цифра не может быть 0
    # \d{1,14} - от 1 до 14 цифр (стандарт E.164)
    pattern = r'^\+?[1-9]\d{1,14}$'
    return re.match(pattern, cleaned_phone) is not None

def require_auth(f):
    """
    Декоратор для проверки аутентификации пользователя
    
    Проверяет наличие user_id в сессии. Если пользователь не авторизован,
    возвращает ошибку 401 для API запросов или перенаправляет на страницу входа.
    
    Использование:
        @app.route('/api/data')
        @require_auth
        def get_data():
            # Этот код выполнится только если пользователь авторизован
            return jsonify({'data': 'secret'})
    
    Args:
        f: Функция-обработчик маршрута
    
    Returns:
        decorated_function: Обернутая функция с проверкой аутентификации
    """
    @wraps(f)  # Сохраняет метаданные оригинальной функции
    def decorated_function(*args, **kwargs):
        # Проверяем наличие user_id в сессии
        if 'user_id' not in session:
            # Если это JSON запрос (API), возвращаем JSON ошибку
            if request.is_json:
                return jsonify({'error': 'Not authenticated'}), 401
            # Иначе перенаправляем на страницу входа
            return redirect('/login')
        # Если пользователь авторизован, выполняем оригинальную функцию
        return f(*args, **kwargs)
    return decorated_function

def require_role(role):
    """
    Декоратор для проверки роли пользователя
    
    Проверяет, что у пользователя есть необходимая роль (admin или manager).
    Используется для ограничения доступа к определенным функциям.
    
    Использование:
        @app.route('/admin/settings')
        @require_auth
        @require_role('admin')
        def admin_settings():
            # Доступ только для администраторов
            return render_template('admin_settings.html')
    
    Args:
        role (str): Требуемая роль ('admin' или 'manager')
    
    Returns:
        decorator: Декоратор для применения к функции
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Проверяем роль пользователя из сессии
            if session.get('user_role') != role:
                # Если роль не совпадает, возвращаем ошибку доступа
                if request.is_json:
                    return jsonify({'error': 'Access denied'}), 403
                return redirect('/login')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def handle_errors(f):
    """
    Декоратор для обработки ошибок в функциях-обработчиках
    
    Перехватывает все исключения, логирует их и возвращает понятный ответ
    пользователю. Предотвращает отображение технических деталей ошибок.
    
    Использование:
        @app.route('/api/data')
        @handle_errors
        def get_data():
            # Если здесь произойдет ошибка, она будет обработана
            return jsonify({'data': data})
    
    Args:
        f: Функция-обработчик маршрута
    
    Returns:
        decorated_function: Обернутая функция с обработкой ошибок
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Пытаемся выполнить функцию
            return f(*args, **kwargs)
        except Exception as e:
            # Логируем ошибку с полным стеком вызовов
            app.logger.error(f'Error in {f.__name__}: {str(e)}', exc_info=True)
            
            # Возвращаем ошибку в формате, соответствующем типу запроса
            if request.is_json:
                # Для API запросов возвращаем JSON
                return jsonify({'error': 'Internal server error', 'message': str(e)}), 500
            # Для HTML запросов возвращаем страницу ошибки
            return render_template('error.html', error=str(e)), 500
    return decorated_function

def log_activity(user_id, action_type, action_description=None, target_type=None, target_id=None, metadata=None):
    """
    Логирование действий пользователя в базу данных
    
    Записывает все действия пользователей в таблицу activity_logs для аудита
    и анализа активности. Используется для отслеживания изменений, входа/выхода,
    отправки сообщений и других операций.
    
    Args:
        user_id (int): ID пользователя, выполнившего действие
        action_type (str): Тип действия (login, logout, send_message, update_delivery и т.д.)
        action_description (str, optional): Текстовое описание действия
        target_type (str, optional): Тип объекта, на который направлено действие (chat, delivery, user)
        target_id (int, optional): ID объекта, на который направлено действие
        metadata (dict, optional): Дополнительные данные в формате JSON
    
    Примеры использования:
        log_activity(user_id, 'login', 'Вход в систему', 'user', user_id)
        log_activity(user_id, 'send_message', 'Отправлено сообщение', 'chat', chat_id, {'message_length': 50})
        log_activity(user_id, 'update_delivery', 'Обновлена доставка', 'delivery', delivery_id)
    """
    conn = get_db_connection()
    try:
        # Вставляем запись о действии в таблицу логов
        conn.execute('''
            INSERT INTO activity_logs (user_id, action_type, action_description, target_type, target_id, metadata, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, 
            action_type, 
            action_description, 
            target_type, 
            target_id, 
            # Преобразуем словарь metadata в JSON строку для хранения в БД
            json.dumps(metadata) if metadata else None,
            # Получаем IP адрес клиента из запроса
            request.remote_addr,
            # Получаем информацию о браузере пользователя
            request.headers.get('User-Agent')
        ))
        conn.commit()
    except Exception as e:
        # Если не удалось записать лог, логируем ошибку, но не прерываем выполнение
        app.logger.error(f'Error logging activity: {str(e)}')
    finally:
        # Всегда закрываем соединение с БД
        conn.close()


def get_system_stats():
    """
    Получение общей статистики системы
    
    Собирает основные метрики системы для отображения на дашбордах:
    - Общее количество чатов
    - Активные чаты (со статусом 'active')
    - Срочные чаты (с приоритетом 'urgent')
    - Общее количество пользователей
    - Количество менеджеров
    - Количество магазинов
    
    Returns:
        dict: Словарь со статистикой:
            {
                'total_chats': int,
                'active_chats': int,
                'urgent_chats': int,
                'total_users': int,
                'total_managers': int,
                'total_shops': int
            }
    
    Использование:
        stats = get_system_stats()
        print(f"Всего чатов: {stats['total_chats']}")
    """
    conn = get_db_connection()

    # Считаем общее количество чатов в системе
    total_chats = conn.execute('SELECT COUNT(*) as count FROM avito_chats').fetchone()['count']

    # Считаем активные чаты (не завершенные, требующие внимания)
    active_chats = conn.execute('SELECT COUNT(*) as count FROM avito_chats WHERE status = "active"').fetchone()['count']

    # Считаем срочные чаты (требующие немедленного ответа)
    urgent_chats = conn.execute('SELECT COUNT(*) as count FROM avito_chats WHERE priority = "urgent"').fetchone()['count']

    # Считаем общее количество пользователей (админы + менеджеры)
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    
    # Считаем только менеджеров (исключая администраторов)
    total_managers = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "manager"').fetchone()['count']

    # Считаем количество магазинов Авито, подключенных к системе
    total_shops = conn.execute('SELECT COUNT(*) as count FROM avito_shops').fetchone()['count']

    conn.close()

    # Возвращаем словарь со всей статистикой
    return {
        'total_chats': total_chats,
        'active_chats': active_chats,
        'urgent_chats': urgent_chats,
        'total_users': total_users,
        'total_managers': total_managers,
        'total_shops': total_shops
    }


# Главная страница - редирект на логин
@app.route('/')
def home():
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user['role'] == 'admin':
            return redirect('/admin/dashboard')
        else:
            return redirect('/manager/dashboard')
    return redirect('/login')


# Страница входа
@app.route('/login', methods=['GET', 'POST'])
@handle_errors
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # Валидация
        if not email or not password:
            return render_template('login.html', error='Заполните все поля')
        
        if not validate_email(email):
            return render_template('login.html', error='Неверный формат email')

        user = authenticate_user(email, password)
        if user:
            session['user_id'] = user['id']
            session['user_role'] = user['role']
            session['login_time'] = datetime.now().isoformat()

            # Логируем вход
            log_activity(user['id'], 'login', f'Вход в систему', 'user', user['id'])

            if user['role'] == 'admin':
                return redirect('/admin/dashboard')
            else:
                return redirect('/manager/dashboard')
        else:
            return render_template('login.html', error='Неверный email или пароль')

    return render_template('login.html')


# Выход
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# Админ панель
@app.route('/admin/dashboard')
@require_auth
@require_role('admin')
@handle_errors
def admin_dashboard():
    user = get_user_by_id(session['user_id'])
    stats = get_system_stats()
    return render_template('admin_dashboard.html', user=user, stats=stats)


# Панель менеджера
@app.route('/manager/dashboard')
@require_auth
@require_role('manager')
@handle_errors
def manager_dashboard():
    user = get_user_by_id(session['user_id'])
    stats = get_system_stats()
    return render_template('manager_dashboard.html', user=user, stats=stats)


# API для получения данных пользователя
@app.route('/api/user')
@require_auth
@handle_errors
def get_current_user():
    user = get_user_by_id(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user)


# API для получения статистики
@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    stats = get_system_stats()
    return jsonify(stats)


# API для получения списка пользователей (только для админа)
@app.route('/api/users')
def get_users():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, email, role, is_active, kpi_score, created_at 
        FROM users 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()

    users_list = [dict(user) for user in users]
    return jsonify(users_list)


# API для получения магазинов
@app.route('/api/shops')
def get_shops():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()

    if session.get('user_role') == 'admin':
        # Админ видит все магазины
        shops = conn.execute('SELECT * FROM avito_shops ORDER BY created_at DESC').fetchall()
    else:
        # Менеджер видит только назначенные магазины
        shops = conn.execute('''
            SELECT s.* FROM avito_shops s
            JOIN manager_assignments ma ON s.id = ma.shop_id
            WHERE ma.manager_id = ? AND s.is_active = 1
            ORDER BY s.created_at DESC
        ''', (session['user_id'],)).fetchall()

    conn.close()

    shops_list = [dict(shop) for shop in shops]
    return jsonify(shops_list)


# API для получения чатов
@app.route('/api/chats')
def get_chats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    show_pool = request.args.get('pool', 'false').lower() == 'true'

    if session.get('user_role') == 'admin':
        # Админ видит все чаты
        if show_pool:
            chats = conn.execute('''
                SELECT c.*, s.name as shop_name, u.username as assigned_manager_name
                FROM avito_chats c
                LEFT JOIN avito_shops s ON c.shop_id = s.id
                LEFT JOIN users u ON c.assigned_manager_id = u.id
                WHERE c.assigned_manager_id IS NULL AND c.status != 'completed'
                ORDER BY c.updated_at DESC
            ''').fetchall()
        else:
            chats = conn.execute('''
                SELECT c.*, s.name as shop_name, u.username as assigned_manager_name
                FROM avito_chats c
                LEFT JOIN avito_shops s ON c.shop_id = s.id
                LEFT JOIN users u ON c.assigned_manager_id = u.id
                ORDER BY c.updated_at DESC
            ''').fetchall()
    else:
        # Менеджер видит свои чаты и пул чатов
        manager_id = session['user_id']
        if show_pool:
            # Показываем только пул чатов
            chats = conn.execute('''
                SELECT c.*, s.name as shop_name, NULL as assigned_manager_name
                FROM avito_chats c
                JOIN avito_shops s ON c.shop_id = s.id
                JOIN manager_assignments ma ON s.id = ma.shop_id
                WHERE ma.manager_id = ? AND c.assigned_manager_id IS NULL AND c.status != 'completed'
                ORDER BY c.updated_at DESC
            ''', (manager_id,)).fetchall()
        else:
            # Показываем назначенные чаты менеджера
            chats = conn.execute('''
                SELECT c.*, s.name as shop_name, u.username as assigned_manager_name
                FROM avito_chats c
                JOIN avito_shops s ON c.shop_id = s.id
                JOIN manager_assignments ma ON s.id = ma.shop_id
                LEFT JOIN users u ON c.assigned_manager_id = u.id
                WHERE ma.manager_id = ? AND (c.assigned_manager_id = ? OR c.assigned_manager_id IS NULL)
                ORDER BY c.updated_at DESC
            ''', (manager_id, manager_id)).fetchall()

    conn.close()

    chats_list = [dict(chat) for chat in chats]
    return jsonify(chats_list)


# API для обновления чата
@app.route('/api/chats/<int:chat_id>', methods=['PUT'])
def update_chat(chat_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    conn = get_db_connection()
    
    try:
        update_fields = []
        update_values = []
        
        if 'status' in data:
            update_fields.append('status = ?')
            update_values.append(data['status'])
        
        if 'priority' in data:
            update_fields.append('priority = ?')
            update_values.append(data['priority'])
        
        if 'assigned_manager_id' in data:
            update_fields.append('assigned_manager_id = ?')
            update_values.append(data['assigned_manager_id'] if data['assigned_manager_id'] else None)
        
        if update_fields:
            update_fields.append('updated_at = CURRENT_TIMESTAMP')
            update_values.append(chat_id)
            
            query = f'UPDATE avito_chats SET {", ".join(update_fields)} WHERE id = ?'
            conn.execute(query, tuple(update_values))
            conn.commit()
        
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# Статические файлы
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('../frontend', filename)


# Страница управления чатами
@app.route('/chats')
def chats_page():
    if 'user_id' not in session:
        return redirect('/login')

    user = get_user_by_id(session['user_id'])
    return render_template('chats.html', user=user)


# Страница управления магазинами
@app.route('/shops')
def shops_page():
    if 'user_id' not in session:
        return redirect('/login')

    user = get_user_by_id(session['user_id'])
    return render_template('shops.html', user=user)


# Страница доставок
@app.route('/deliveries')
def deliveries_page():
    if 'user_id' not in session:
        return redirect('/login')

    user = get_user_by_id(session['user_id'])
    return render_template('deliveries.html', user=user)


# Страница аналитики
@app.route('/analytics')
def analytics_page():
    if 'user_id' not in session:
        return redirect('/login')

    user = get_user_by_id(session['user_id'])
    return render_template('analytics.html', user=user)


# Страница настроек
@app.route('/settings')
def settings_page():
    if 'user_id' not in session:
        return redirect('/login')

    user = get_user_by_id(session['user_id'])
    return render_template('settings.html', user=user)

# Страница управления менеджерами (только админ)
@app.route('/managers')
@require_auth
@require_role('admin')
@handle_errors
def managers_page():
    user = get_user_by_id(session['user_id'])
    return render_template('managers.html', user=user)

# Страница управления быстрыми ответами
@app.route('/quick-replies')
@require_auth
@handle_errors
def quick_replies_page():
    user = get_user_by_id(session['user_id'])
    return render_template('quick_replies.html', user=user)

# CSS файлы
@app.route('/css/<filename>')
def serve_css(filename):
    return send_from_directory('../frontend/css', filename)


# ==================== МОДУЛЬ МАГАЗИНОВ ====================

# API для создания магазина (только админ)
@app.route('/api/shops', methods=['POST'])
@require_auth
@require_role('admin')
@handle_errors
def create_shop():
    data = request.get_json()
    
    # Валидация
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    name = data.get('name', '').strip()
    shop_url = data.get('shop_url', '').strip()
    api_key = data.get('api_key', '').strip()
    
    if not name or not shop_url:
        return jsonify({'error': 'Name and shop_url are required'}), 400
    
    # Валидация URL
    if not shop_url.startswith(('http://', 'https://')):
        return jsonify({'error': 'Invalid shop URL'}), 400
    
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            INSERT INTO avito_shops (name, shop_url, api_key, is_active)
            VALUES (?, ?, ?, ?)
        ''', (name, shop_url, api_key, data.get('is_active', True)))
        shop_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': shop_id}), 201
    except Exception as e:
        conn.close()
        if 'UNIQUE constraint' in str(e):
            return jsonify({'error': 'Shop with this URL already exists'}), 400
        return jsonify({'error': str(e)}), 400


# API для обновления магазина
@app.route('/api/shops/<int:shop_id>', methods=['PUT'])
def update_shop(shop_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    conn = get_db_connection()
    
    try:
        conn.execute('''
            UPDATE avito_shops 
            SET name = ?, shop_url = ?, api_key = ?, is_active = ?
            WHERE id = ?
        ''', (data.get('name'), data.get('shop_url'), data.get('api_key'), 
              data.get('is_active'), shop_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# API для удаления магазина
@app.route('/api/shops/<int:shop_id>', methods=['DELETE'])
def delete_shop(shop_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    conn.execute('DELETE FROM avito_shops WHERE id = ?', (shop_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True}), 200


# API для назначения менеджера на магазин
@app.route('/api/shops/<int:shop_id>/assign', methods=['POST'])
def assign_manager(shop_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    manager_id = data.get('manager_id')
    
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT OR IGNORE INTO manager_assignments (manager_id, shop_id)
            VALUES (?, ?)
        ''', (manager_id, shop_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# API для получения статистики по магазину
@app.route('/api/shops/<int:shop_id>/stats')
def get_shop_stats(shop_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    stats = {
        'total_chats': conn.execute('SELECT COUNT(*) as count FROM avito_chats WHERE shop_id = ?', (shop_id,)).fetchone()['count'],
        'active_chats': conn.execute('SELECT COUNT(*) as count FROM avito_chats WHERE shop_id = ? AND status = "active"', (shop_id,)).fetchone()['count'],
        'urgent_chats': conn.execute('SELECT COUNT(*) as count FROM avito_chats WHERE shop_id = ? AND priority = "urgent"', (shop_id,)).fetchone()['count'],
    }
    conn.close()
    return jsonify(stats)


# API для получения назначенных менеджеров магазина
@app.route('/api/shops/<int:shop_id>/managers')
def get_shop_managers(shop_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    managers = conn.execute('''
        SELECT u.id, u.username, u.email
        FROM users u
        JOIN manager_assignments ma ON u.id = ma.manager_id
        WHERE ma.shop_id = ?
    ''', (shop_id,)).fetchall()
    conn.close()
    
    return jsonify([dict(manager) for manager in managers])


# ==================== МОДУЛЬ ДОСТАВОК ====================

# API для получения доставок
@app.route('/api/deliveries')
def get_deliveries():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    
    try:
    if session.get('user_role') == 'admin':
            # Оптимизированный запрос с индексами
        deliveries = conn.execute('''
            SELECT d.*, c.client_name, c.client_phone, c.id as chat_id, u.username as manager_name
            FROM deliveries d
            LEFT JOIN avito_chats c ON d.chat_id = c.id
            LEFT JOIN users u ON d.manager_id = u.id
            ORDER BY d.updated_at DESC
                LIMIT 1000
        ''').fetchall()
    else:
            # Оптимизированный запрос для менеджера
        deliveries = conn.execute('''
            SELECT d.*, c.client_name, c.client_phone, c.id as chat_id
            FROM deliveries d
            LEFT JOIN avito_chats c ON d.chat_id = c.id
            WHERE d.manager_id = ?
            ORDER BY d.updated_at DESC
                LIMIT 1000
        ''', (session['user_id'],)).fetchall()
    
        # Преобразуем в словари и добавляем поддержку нескольких клиентов
        result = []
        for delivery in deliveries:
            delivery_dict = dict(delivery)
            # Если есть несколько клиентов для одной доставки (через связанные чаты)
            # Это можно расширить в будущем для поддержки множественных клиентов
            result.append(delivery_dict)
        
        return jsonify(result)
    finally:
    conn.close()


# API для создания доставки
@app.route('/api/deliveries', methods=['POST'])
def create_delivery():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    conn = get_db_connection()
    
    try:
        chat_id = data.get('chat_id')
        
        # Проверяем, что chat_id обязателен (доставки создаются только из чатов)
        if not chat_id:
            conn.close()
            return jsonify({'error': 'chat_id is required. Deliveries can only be created from chats.'}), 400
        
        # Проверяем, что чат еще не в доставках
        existing = conn.execute('SELECT id FROM deliveries WHERE chat_id = ?', (chat_id,)).fetchone()
        if existing:
            conn.close()
            return jsonify({'error': 'This chat is already in deliveries'}), 400
        
        # Создаем доставку со статусом "в работе" по умолчанию
        cursor = conn.execute('''
            INSERT INTO deliveries (chat_id, manager_id, delivery_status, address, tracking_number, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (chat_id, session['user_id'], data.get('status', 'in_work'),
              data.get('address'), data.get('tracking_number'), data.get('notes')))
        
        # Обновляем приоритет чата на delivery, если chat_id указан
        if chat_id:
            conn.execute('UPDATE avito_chats SET priority = "delivery" WHERE id = ?', (chat_id,))
        
        log_activity(session['user_id'], 'create_delivery', 
                    f'Создана доставка ID: {cursor.lastrowid}', 'delivery', cursor.lastrowid)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': cursor.lastrowid}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# API для обновления статуса доставки
@app.route('/api/deliveries/<int:delivery_id>', methods=['PUT'])
def update_delivery(delivery_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    conn = get_db_connection()
    
    try:
        # Валидация статуса
        valid_statuses = ['processing', 'picking', 'shipped', 'in_transit', 'delivered', 'cancelled']
        new_status = data.get('status')
        if new_status and new_status not in valid_statuses:
            conn.close()
            return jsonify({'error': 'Invalid status'}), 400
        
        # Обновляем поля доставки
        update_fields = []
        update_values = []
        
        if 'status' in data:
            update_fields.append('delivery_status = ?')
            update_values.append(data.get('status'))
        
        if 'address' in data:
            update_fields.append('address = ?')
            update_values.append(data.get('address'))
        
        if 'tracking_number' in data:
            update_fields.append('tracking_number = ?')
            update_values.append(data.get('tracking_number'))
        
        if 'notes' in data:
            update_fields.append('notes = ?')
            update_values.append(data.get('notes'))
        
        if 'chat_id' in data:
            update_fields.append('chat_id = ?')
            update_values.append(data.get('chat_id') if data.get('chat_id') else None)
        
        if update_fields:
            update_fields.append('updated_at = CURRENT_TIMESTAMP')
            update_values.append(delivery_id)
            query = f'UPDATE deliveries SET {", ".join(update_fields)} WHERE id = ?'
            conn.execute(query, tuple(update_values))
        
        # Логируем изменение
        log_activity(session['user_id'], 'update_delivery', 
                    f'Обновлена доставка ID: {delivery_id}', 'delivery', delivery_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# API для batch обновления статусов доставок
@app.route('/api/deliveries/batch', methods=['PUT'])
@require_auth
@handle_errors
def batch_update_deliveries():
    """Массовое обновление статусов доставок для повышения производительности"""
    data = request.get_json()
    
    if not data or 'updates' not in data:
        return jsonify({'error': 'No updates provided'}), 400
    
    updates = data.get('updates', [])
    if not isinstance(updates, list) or len(updates) == 0:
        return jsonify({'error': 'Updates must be a non-empty array'}), 400
    
    if len(updates) > 100:  # Ограничение на количество обновлений за раз
        return jsonify({'error': 'Too many updates. Maximum 100 at once'}), 400
    
    conn = get_db_connection()
    # Новые статусы: в работе, свободно, закрыт, на доставку, отказался
    valid_statuses = ['in_work', 'free', 'closed', 'on_delivery', 'refused']
    updated_count = 0
    
    try:
        for update in updates:
            delivery_id = update.get('id')
            if not delivery_id:
                continue
            
            # Проверка прав доступа для менеджеров
            if session.get('user_role') != 'admin':
                # Менеджер может обновлять только свои доставки
                check = conn.execute(
                    'SELECT manager_id FROM deliveries WHERE id = ?',
                    (delivery_id,)
                ).fetchone()
                if not check or check['manager_id'] != session['user_id']:
                    continue
            
            update_fields = []
            update_values = []
            
            if 'status' in update:
                status = update.get('status')
                if status in valid_statuses:
                    update_fields.append('delivery_status = ?')
                    update_values.append(status)
            
            if 'address' in update:
                update_fields.append('address = ?')
                update_values.append(update.get('address'))
            
            if 'tracking_number' in update:
                update_fields.append('tracking_number = ?')
                update_values.append(update.get('tracking_number'))
            
            if 'notes' in update:
                update_fields.append('notes = ?')
                update_values.append(update.get('notes'))
            
            if update_fields:
                update_fields.append('updated_at = CURRENT_TIMESTAMP')
                update_values.append(delivery_id)
                query = f'UPDATE deliveries SET {", ".join(update_fields)} WHERE id = ?'
                conn.execute(query, tuple(update_values))
                updated_count += 1
        
        conn.commit()
        conn.close()
        
        # Логируем batch операцию
        log_activity(session['user_id'], 'batch_update_deliveries', 
                    f'Массовое обновление {updated_count} доставок', 'delivery', None)
        
        return jsonify({'success': True, 'updated': updated_count}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# ==================== МОДУЛЬ СООБЩЕНИЙ ====================

# API для получения сообщений чата (оптимизировано с пагинацией)
@app.route('/api/chats/<int:chat_id>/messages')
def get_chat_messages(chat_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Параметры пагинации
    limit = min(int(request.args.get('limit', 100)), 500)  # Максимум 500 сообщений
    offset = int(request.args.get('offset', 0))
    before_id = request.args.get('before_id')  # Для загрузки старых сообщений
    
    conn = get_db_connection()
    
    # Базовый запрос
    query = '''
        SELECT m.*, u.username as manager_name
        FROM avito_messages m
        LEFT JOIN users u ON m.manager_id = u.id
        WHERE m.chat_id = ?
    '''
    params = [chat_id]
    
    # Если указан before_id, загружаем сообщения до этого ID (для прокрутки вверх)
    if before_id:
        query += ' AND m.id < ?'
        params.append(before_id)
    
    query += ' ORDER BY m.timestamp DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    messages = conn.execute(query, tuple(params)).fetchall()
    
    # Получаем общее количество сообщений для пагинации
    total_count = conn.execute(
        'SELECT COUNT(*) as count FROM avito_messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()['count']
    
    conn.close()

    # Логируем открытие чата
    log_activity(session['user_id'], 'open_chat', 
                f'Открыт чат ID: {chat_id}', 'chat', chat_id)
    
    # Возвращаем в обратном порядке (новые первыми, но потом перевернем на клиенте)
    messages_list = [dict(msg) for msg in reversed(messages)]
    
    return jsonify({
        'messages': messages_list,
        'total': total_count,
        'limit': limit,
        'offset': offset,
        'has_more': offset + limit < total_count
    })


# API для отправки сообщения
@app.route('/api/chats/<int:chat_id>/messages', methods=['POST'])
@require_auth
@handle_errors
def send_message(chat_id):
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    message = data.get('message', '').strip()
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    if len(message) > 5000:
        return jsonify({'error': 'Message too long (max 5000 characters)'}), 400
    
    conn = get_db_connection()
    try:
        # Проверяем существование чата
        chat = conn.execute('SELECT id FROM avito_chats WHERE id = ?', (chat_id,)).fetchone()
        if not chat:
            conn.close()
            return jsonify({'error': 'Chat not found'}), 404
        
        user = get_user_by_id(session['user_id'])
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Добавляем сообщение с manager_id
        manager_id = session['user_id'] if session.get('user_role') == 'manager' else None
        cursor = conn.execute('''
            INSERT INTO avito_messages (chat_id, message_text, message_type, sender_name, manager_id)
            VALUES (?, ?, 'outgoing', ?, ?)
        ''', (chat_id, message, user['username'], manager_id))
        
        # Обновляем последнее сообщение в чате и назначаем менеджера если чат был в пуле
        conn.execute('''
            UPDATE avito_chats 
            SET last_message = ?, updated_at = CURRENT_TIMESTAMP,
                assigned_manager_id = COALESCE(assigned_manager_id, ?)
            WHERE id = ?
        ''', (message, manager_id, chat_id))
        
        # Логируем событие
        conn.execute('''
            INSERT INTO analytics_logs (event_type, user_id, chat_id, metadata)
            VALUES ('message_sent', ?, ?, ?)
        ''', (session['user_id'], chat_id, json.dumps({'message_length': len(message)})))
        
        # Логируем действие
        log_activity(session['user_id'], 'send_message', 
                    f'Отправлено сообщение в чат ID: {chat_id}', 'chat', chat_id,
                    {'message_length': len(message)})
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': cursor.lastrowid}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# API для получения шаблонов ответов
@app.route('/api/templates')
def get_templates():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    templates = conn.execute('''
        SELECT * FROM message_templates 
        WHERE is_active = 1 
        ORDER BY category, name
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(template) for template in templates])


# API для получения быстрых ответов
@app.route('/api/quick-replies')
def get_quick_replies():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    replies = conn.execute('''
        SELECT * FROM quick_replies 
        WHERE is_active = 1 
        ORDER BY shortcut
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(reply) for reply in replies])

# API для получения всех быстрых ответов (включая неактивные)
@app.route('/api/quick-replies/all')
@require_auth
@handle_errors
def get_all_quick_replies():
    """Получение всех быстрых ответов (для управления)"""
    conn = get_db_connection()
    replies = conn.execute('''
        SELECT * FROM quick_replies 
        ORDER BY is_active DESC, shortcut
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(reply) for reply in replies])

# API для создания быстрого ответа
@app.route('/api/quick-replies', methods=['POST'])
@require_auth
@handle_errors
def create_quick_reply():
    """Создание быстрого ответа"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    shortcut = data.get('shortcut', '').strip()
    message = data.get('message', '').strip()
    
    if not shortcut or not message:
        return jsonify({'error': 'Shortcut and message are required'}), 400
    
    if not shortcut.startswith('/'):
        shortcut = '/' + shortcut
    
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            INSERT INTO quick_replies (shortcut, message, created_by, is_active)
            VALUES (?, ?, ?, ?)
        ''', (shortcut, message, session['user_id'], True))
        reply_id = cursor.lastrowid
        
        log_activity(session['user_id'], 'create_quick_reply', 
                    f'Создан быстрый ответ: {shortcut}', 'quick_reply', reply_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': reply_id}), 201
    except Exception as e:
        conn.close()
        if 'UNIQUE constraint' in str(e):
            return jsonify({'error': 'Quick reply with this shortcut already exists'}), 400
        return jsonify({'error': str(e)}), 400

# API для обновления быстрого ответа
@app.route('/api/quick-replies/<int:reply_id>', methods=['PUT'])
@require_auth
@handle_errors
def update_quick_reply(reply_id):
    """Обновление быстрого ответа"""
    data = request.get_json()
    conn = get_db_connection()
    
    try:
        update_fields = []
        update_values = []
        
        if 'shortcut' in data:
            shortcut = data['shortcut'].strip()
            if not shortcut.startswith('/'):
                shortcut = '/' + shortcut
            update_fields.append('shortcut = ?')
            update_values.append(shortcut)
        
        if 'message' in data:
            update_fields.append('message = ?')
            update_values.append(data['message'].strip())
        
        if 'is_active' in data:
            update_fields.append('is_active = ?')
            update_values.append(data['is_active'])
        
        if update_fields:
            update_values.append(reply_id)
            query = f'UPDATE quick_replies SET {", ".join(update_fields)} WHERE id = ?'
            conn.execute(query, tuple(update_values))
            
            log_activity(session['user_id'], 'update_quick_reply', 
                        f'Обновлен быстрый ответ ID: {reply_id}', 'quick_reply', reply_id)
            
            conn.commit()
        
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для удаления быстрого ответа
@app.route('/api/quick-replies/<int:reply_id>', methods=['DELETE'])
@require_auth
@handle_errors
def delete_quick_reply(reply_id):
    """Удаление быстрого ответа (деактивация)"""
    conn = get_db_connection()
    try:
        conn.execute('UPDATE quick_replies SET is_active = 0 WHERE id = ?', (reply_id,))
        
        log_activity(session['user_id'], 'delete_quick_reply', 
                    f'Удален быстрый ответ ID: {reply_id}', 'quick_reply', reply_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# ==================== МОДУЛЬ АНАЛИТИКИ ====================

# API для получения аналитики
@app.route('/api/analytics')
def get_analytics():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    user_id = session['user_id']
    role = session.get('user_role')
    
    # Статистика ответов
    if role == 'admin':
        response_stats = conn.execute('''
            SELECT 
                AVG(response_timer) as avg_response_time,
                COUNT(*) as total_chats,
                SUM(CASE WHEN priority = 'urgent' THEN 1 ELSE 0 END) as urgent_count
            FROM avito_chats
        ''').fetchone()
    else:
        response_stats = conn.execute('''
            SELECT 
                AVG(response_timer) as avg_response_time,
                COUNT(*) as total_chats,
                SUM(CASE WHEN priority = 'urgent' THEN 1 ELSE 0 END) as urgent_count
            FROM avito_chats
            WHERE assigned_manager_id = ?
        ''', (user_id,)).fetchone()
    
    # KPI менеджеров
    if role == 'admin':
        kpi_stats = conn.execute('''
            SELECT u.id, u.username, u.kpi_score, 
                   COUNT(DISTINCT c.id) as total_chats,
                   AVG(c.response_timer) as avg_response_time
            FROM users u
            LEFT JOIN avito_chats c ON u.id = c.assigned_manager_id
            WHERE u.role = 'manager'
            GROUP BY u.id
        ''').fetchall()
    else:
        kpi_stats = conn.execute('''
            SELECT u.id, u.username, u.kpi_score, 
                   COUNT(DISTINCT c.id) as total_chats,
                   AVG(c.response_timer) as avg_response_time
            FROM users u
            LEFT JOIN avito_chats c ON u.id = c.assigned_manager_id
            WHERE u.id = ?
            GROUP BY u.id
        ''', (user_id,)).fetchall()
    
    # Конверсия в заказы
    conversion_stats = conn.execute('''
        SELECT 
            COUNT(DISTINCT c.id) as total_chats,
            COUNT(DISTINCT o.id) as total_orders,
            ROUND(COUNT(DISTINCT o.id) * 100.0 / COUNT(DISTINCT c.id), 2) as conversion_rate
        FROM avito_chats c
        LEFT JOIN client_orders o ON c.id = o.chat_id
    ''').fetchone()
    
    conn.close()
    
    return jsonify({
        'response_stats': dict(response_stats),
        'kpi_stats': [dict(stat) for stat in kpi_stats],
        'conversion_stats': dict(conversion_stats)
    })


# ==================== МОДУЛЬ АВТОМАТИЗАЦИИ ====================

# API для получения правил автоматизации
@app.route('/api/automation')
def get_automation_rules():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    rules = conn.execute('''
        SELECT * FROM automation_rules 
        WHERE is_active = 1 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(rule) for rule in rules])


# API для создания правила автоматизации
@app.route('/api/automation', methods=['POST'])
def create_automation_rule():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    conn = get_db_connection()
    
    try:
        cursor = conn.execute('''
            INSERT INTO automation_rules (name, trigger_type, trigger_condition, action_type, action_data, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data.get('name'), data.get('trigger_type'), json.dumps(data.get('trigger_condition')),
              data.get('action_type'), json.dumps(data.get('action_data')), session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': cursor.lastrowid}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# ==================== МОДУЛЬ KPI И ШТРАФОВ ====================

# API для получения KPI менеджера
@app.route('/api/kpi/<int:user_id>')
def get_manager_kpi(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Проверяем права доступа
    if session.get('user_role') != 'admin' and session['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    
    # Получаем настройки KPI
    kpi_settings = conn.execute('SELECT * FROM kpi_settings').fetchall()
    
    # Получаем историю KPI
    kpi_history = conn.execute('''
        SELECT * FROM kpi_history 
        WHERE user_id = ? 
        ORDER BY period_end DESC 
        LIMIT 12
    ''', (user_id,)).fetchall()
    
    # Получаем текущие показатели
    user = conn.execute('SELECT kpi_score FROM users WHERE id = ?', (user_id,)).fetchone()
    
    conn.close()
    
    return jsonify({
        'settings': [dict(setting) for setting in kpi_settings],
        'history': [dict(record) for record in kpi_history],
        'current_score': user['kpi_score'] if user else 0
    })


# ==================== МОДУЛЬ НАСТРОЕК СИСТЕМЫ ====================

# API для получения настроек системы
@app.route('/api/settings')
def get_system_settings():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = get_db_connection()
    settings = conn.execute('SELECT * FROM system_settings').fetchall()
    conn.close()
    
    settings_dict = {}
    for setting in settings:
        value = setting['setting_value']
        if setting['setting_type'] == 'number':
            value = float(value) if '.' in value else int(value)
        elif setting['setting_type'] == 'boolean':
            value = value.lower() == 'true'
        elif setting['setting_type'] == 'json':
            value = json.loads(value)
        settings_dict[setting['setting_key']] = value
    
    return jsonify(settings_dict)


# API для обновления настроек системы
@app.route('/api/settings', methods=['PUT'])
def update_system_settings():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    conn = get_db_connection()
    
    try:
        for key, value in data.items():
            setting_type = 'string'
            if isinstance(value, bool):
                setting_type = 'boolean'
                value = 'true' if value else 'false'
            elif isinstance(value, (int, float)):
                setting_type = 'number'
                value = str(value)
            elif isinstance(value, dict):
                setting_type = 'json'
                value = json.dumps(value)
            
            conn.execute('''
                UPDATE system_settings 
                SET setting_value = ?, setting_type = ?, updated_at = CURRENT_TIMESTAMP
                WHERE setting_key = ?
            ''', (str(value), setting_type, key))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# API для получения настроек пользователя (тема и т.д.)
@app.route('/api/user/settings')
def get_user_settings_api():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    settings = get_user_settings(session['user_id'])
    return jsonify(settings if settings else {})


# API для обновления настроек пользователя
@app.route('/api/user/settings', methods=['PUT'])
def update_user_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    conn = get_db_connection()
    
    try:
        # Проверяем существование настроек
        existing = conn.execute('SELECT id FROM user_settings WHERE user_id = ?', (session['user_id'],)).fetchone()
        
        if existing:
            conn.execute('''
                UPDATE user_settings 
                SET theme = ?, colors = ?, sound_alerts = ?, push_notifications = ?
                WHERE user_id = ?
            ''', (data.get('theme'), json.dumps(data.get('colors', {})), 
                  data.get('sound_alerts', True), data.get('push_notifications', True), session['user_id']))
        else:
            conn.execute('''
                INSERT INTO user_settings (user_id, theme, colors, sound_alerts, push_notifications)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], data.get('theme', 'dark'), json.dumps(data.get('colors', {})),
                  data.get('sound_alerts', True), data.get('push_notifications', True)))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400


# ==================== НОВЫЕ ФУНКЦИИ ====================

# API для экспорта данных в CSV
# ==================== ЭКСПОРТ ДАННЫХ ====================

@app.route('/api/export/<data_type>')
@require_auth
@handle_errors
def export_data(data_type):
    """Экспорт данных в CSV формат"""
    import csv
    from io import StringIO
    
    conn = get_db_connection()
    output = StringIO()
    writer = csv.writer(output)
    
    if data_type == 'chats':
        if session.get('user_role') == 'admin':
            chats = conn.execute('''
                SELECT c.*, s.name as shop_name 
                FROM avito_chats c
                LEFT JOIN avito_shops s ON c.shop_id = s.id
                ORDER BY c.created_at DESC
            ''').fetchall()
        else:
            chats = conn.execute('''
                SELECT c.*, s.name as shop_name 
                FROM avito_chats c
                JOIN avito_shops s ON c.shop_id = s.id
                JOIN manager_assignments ma ON s.id = ma.shop_id
                WHERE ma.manager_id = ?
                ORDER BY c.created_at DESC
            ''', (session['user_id'],)).fetchall()
        
        writer.writerow(['ID', 'Магазин', 'Клиент', 'Телефон', 'Приоритет', 'Статус', 'Последнее сообщение', 'Создан'])
        for chat in chats:
            writer.writerow([
                chat['id'], chat['shop_name'], chat['client_name'], 
                chat['client_phone'], chat['priority'], chat['status'],
                chat['last_message'], chat['created_at']
            ])
    
    elif data_type == 'clients':
        clients = conn.execute('SELECT * FROM clients ORDER BY created_at DESC').fetchall()
        writer.writerow(['ID', 'Имя', 'Телефон', 'Email', 'Заказов', 'Потрачено', 'Создан'])
        for client in clients:
            writer.writerow([
                client['id'], client['name'], client['phone'], 
                client['email'] or '', client['total_orders'], 
                client['total_spent'], client['created_at']
            ])
    
    elif data_type == 'deliveries':
        """
        Экспорт доставок в CSV формат
        
        Экспортирует все доставки с полной информацией:
        - Для администраторов: все доставки
        - Для менеджеров: только свои доставки
        """
        if session.get('user_role') == 'admin':
            deliveries = conn.execute('''
                SELECT d.*, c.client_name, c.client_phone, u.username as manager_name
                FROM deliveries d
                LEFT JOIN avito_chats c ON d.chat_id = c.id
                LEFT JOIN users u ON d.manager_id = u.id
                ORDER BY d.created_at DESC
            ''').fetchall()
        else:
            deliveries = conn.execute('''
                SELECT d.*, c.client_name, c.client_phone
                FROM deliveries d
                LEFT JOIN avito_chats c ON d.chat_id = c.id
                WHERE d.manager_id = ?
                ORDER BY d.created_at DESC
            ''', (session['user_id'],)).fetchall()
        
        # Заголовки CSV файла (упрощенный формат)
        writer.writerow([
            'ID', 'Клиент', 'Телефон', 'Адрес', 
            'Статус', 'Менеджер', 'Создано', 'Обновлено'
        ])
        
        # Маппинг статусов для читаемости
        status_map = {
            'in_work': 'В работе',
            'free': 'Свободно',
            'on_delivery': 'На доставку',
            'closed': 'Закрыт',
            'refused': 'Отказался'
        }
        
        # Данные доставок
        for delivery in deliveries:
            status = delivery.get('delivery_status', 'in_work')
            writer.writerow([
                delivery['id'],
                delivery.get('client_name', ''),
                delivery.get('client_phone', ''),
                delivery.get('address', ''),
                status_map.get(status, status),
                delivery.get('manager_name', '') if session.get('user_role') == 'admin' else '',
                delivery.get('created_at', ''),
                delivery.get('updated_at', '')
            ])
    
    elif data_type == 'analytics':
        if session.get('user_role') != 'admin':
            conn.close()
            return jsonify({'error': 'Access denied'}), 403
        
        logs = conn.execute('''
            SELECT * FROM analytics_logs 
            ORDER BY created_at DESC 
            LIMIT 10000
        ''').fetchall()
        writer.writerow(['ID', 'Тип события', 'Пользователь', 'Чат', 'Магазин', 'Метаданные', 'Дата'])
        for log in logs:
            writer.writerow([
                log['id'], log['event_type'], log['user_id'], 
                log['chat_id'] or '', log['shop_id'] or '',
                log['metadata'] or '', log['created_at']
            ])
    
    conn.close()
    
    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={data_type}_export_{datetime.now().strftime("%Y%m%d")}.csv'}
    )


# API для получения уведомлений
@app.route('/api/notifications')
@require_auth
@handle_errors
def get_notifications():
    """Получение уведомлений для пользователя"""
    conn = get_db_connection()
    
    # Получаем срочные чаты
    if session.get('user_role') == 'admin':
        urgent_chats = conn.execute('''
            SELECT COUNT(*) as count FROM avito_chats 
            WHERE priority = 'urgent' AND status != 'completed'
        ''').fetchone()['count']
    else:
        urgent_chats = conn.execute('''
            SELECT COUNT(*) as count FROM avito_chats c
            JOIN avito_shops s ON c.shop_id = s.id
            JOIN manager_assignments ma ON s.id = ma.shop_id
            WHERE ma.manager_id = ? AND c.priority = 'urgent' AND c.status != 'completed'
        ''', (session['user_id'],)).fetchone()['count']
    
    # Получаем непрочитанные чаты
    if session.get('user_role') == 'admin':
        unread_chats = conn.execute('''
            SELECT COUNT(*) as count FROM avito_chats 
            WHERE unread_count > 0 AND status != 'completed'
        ''').fetchone()['count']
    else:
        unread_chats = conn.execute('''
            SELECT COUNT(*) as count FROM avito_chats c
            JOIN avito_shops s ON c.shop_id = s.id
            JOIN manager_assignments ma ON s.id = ma.shop_id
            WHERE ma.manager_id = ? AND c.unread_count > 0 AND c.status != 'completed'
        ''', (session['user_id'],)).fetchone()['count']
    
    conn.close()
    
    notifications = []
    if urgent_chats > 0:
        notifications.append({
            'type': 'urgent',
            'title': f'{urgent_chats} срочных чатов',
            'message': f'Требуется немедленное внимание',
            'count': urgent_chats
        })
    
    if unread_chats > 0:
        notifications.append({
            'type': 'unread',
            'title': f'{unread_chats} непрочитанных чатов',
            'message': f'Новые сообщения требуют ответа',
            'count': unread_chats
        })
    
    return jsonify(notifications)


# API для получения графиков аналитики
@app.route('/api/analytics/charts')
@require_auth
@handle_errors
def get_analytics_charts():
    """Получение данных для графиков"""
    conn = get_db_connection()
    user_id = session['user_id']
    role = session.get('user_role')
    
    # График чатов по дням (последние 30 дней)
    if role == 'admin':
        daily_chats = conn.execute('''
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM avito_chats
            WHERE created_at >= datetime('now', '-30 days')
            GROUP BY DATE(created_at)
            ORDER BY date
        ''').fetchall()
    else:
        daily_chats = conn.execute('''
            SELECT DATE(c.created_at) as date, COUNT(*) as count
            FROM avito_chats c
            JOIN avito_shops s ON c.shop_id = s.id
            JOIN manager_assignments ma ON s.id = ma.shop_id
            WHERE ma.manager_id = ? AND c.created_at >= datetime('now', '-30 days')
            GROUP BY DATE(c.created_at)
            ORDER BY date
        ''', (user_id,)).fetchall()
    
    # График по приоритетам
    if role == 'admin':
        priority_stats = conn.execute('''
            SELECT priority, COUNT(*) as count
            FROM avito_chats
            WHERE status != 'completed'
            GROUP BY priority
        ''').fetchall()
    else:
        priority_stats = conn.execute('''
            SELECT c.priority, COUNT(*) as count
            FROM avito_chats c
            JOIN avito_shops s ON c.shop_id = s.id
            JOIN manager_assignments ma ON s.id = ma.shop_id
            WHERE ma.manager_id = ? AND c.status != 'completed'
            GROUP BY c.priority
        ''', (user_id,)).fetchall()
    
    # График активности по часам
    if role == 'admin':
        hourly_activity = conn.execute('''
            SELECT strftime('%H', created_at) as hour, COUNT(*) as count
            FROM analytics_logs
            WHERE created_at >= datetime('now', '-7 days')
            GROUP BY hour
            ORDER BY hour
        ''').fetchall()
    else:
        hourly_activity = conn.execute('''
            SELECT strftime('%H', created_at) as hour, COUNT(*) as count
            FROM analytics_logs
            WHERE user_id = ? AND created_at >= datetime('now', '-7 days')
            GROUP BY hour
            ORDER BY hour
        ''', (user_id,)).fetchall()
    
    conn.close()
    
    return jsonify({
        'daily_chats': [{'date': str(row['date']), 'count': row['count']} for row in daily_chats],
        'priority_stats': [{'priority': row['priority'], 'count': row['count']} for row in priority_stats],
        'hourly_activity': [{'hour': int(row['hour']), 'count': row['count']} for row in hourly_activity]
    })


# API для поиска (улучшенный)
@app.route('/api/search')
@require_auth
@handle_errors
def search():
    """Универсальный поиск"""
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all')  # all, chats, clients, shops
    
    if not query or len(query) < 2:
        return jsonify({'error': 'Query too short'}), 400
    
    conn = get_db_connection()
    results = {
        'chats': [],
        'clients': [],
        'shops': []
    }
    
    if search_type in ('all', 'chats'):
        if session.get('user_role') == 'admin':
            chats = conn.execute('''
                SELECT c.*, s.name as shop_name 
                FROM avito_chats c
                LEFT JOIN avito_shops s ON c.shop_id = s.id
                WHERE c.client_name LIKE ? OR c.client_phone LIKE ? OR c.last_message LIKE ?
                ORDER BY c.updated_at DESC
                LIMIT 50
            ''', (f'%{query}%', f'%{query}%', f'%{query}%')).fetchall()
        else:
            chats = conn.execute('''
                SELECT c.*, s.name as shop_name 
                FROM avito_chats c
                JOIN avito_shops s ON c.shop_id = s.id
                JOIN manager_assignments ma ON s.id = ma.shop_id
                WHERE ma.manager_id = ? AND (c.client_name LIKE ? OR c.client_phone LIKE ? OR c.last_message LIKE ?)
                ORDER BY c.updated_at DESC
                LIMIT 50
            ''', (session['user_id'], f'%{query}%', f'%{query}%', f'%{query}%')).fetchall()
        results['chats'] = [dict(chat) for chat in chats]
    
    if search_type in ('all', 'clients'):
        clients = conn.execute('''
            SELECT * FROM clients
            WHERE name LIKE ? OR phone LIKE ? OR email LIKE ?
            ORDER BY updated_at DESC
            LIMIT 50
        ''', (f'%{query}%', f'%{query}%', f'%{query}%')).fetchall()
        results['clients'] = [dict(client) for client in clients]
    
    if search_type in ('all', 'shops') and session.get('user_role') == 'admin':
        shops = conn.execute('''
            SELECT * FROM avito_shops
            WHERE name LIKE ? OR shop_url LIKE ?
            ORDER BY created_at DESC
            LIMIT 50
        ''', (f'%{query}%', f'%{query}%')).fetchall()
        results['shops'] = [dict(shop) for shop in shops]
    
    conn.close()
    return jsonify(results)


# ==================== МОДУЛЬ УПРАВЛЕНИЯ МЕНЕДЖЕРАМИ ====================

# API для создания менеджера (только админ)
@app.route('/api/managers', methods=['POST'])
@require_auth
@require_role('admin')
@handle_errors
def create_manager():
    """Создание нового менеджера админом"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    salary = data.get('salary', 0)
    
    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password are required'}), 400
    
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    import hashlib
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            INSERT INTO users (username, email, password, role, salary, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, email, hashed_password, 'manager', salary, True))
        manager_id = cursor.lastrowid
        
        # Логируем действие
        log_activity(session['user_id'], 'create_manager', 
                    f'Создан менеджер: {username} ({email})', 'user', manager_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': manager_id}), 201
    except Exception as e:
        conn.close()
        if 'UNIQUE constraint' in str(e):
            return jsonify({'error': 'User with this email already exists'}), 400
        return jsonify({'error': str(e)}), 400

# API для обновления менеджера
@app.route('/api/managers/<int:manager_id>', methods=['PUT'])
@require_auth
@require_role('admin')
@handle_errors
def update_manager(manager_id):
    """Обновление данных менеджера"""
    data = request.get_json()
    conn = get_db_connection()
    
    try:
        update_fields = []
        update_values = []
        
        if 'username' in data:
            update_fields.append('username = ?')
            update_values.append(data['username'])
        
        if 'email' in data:
            if not validate_email(data['email']):
                return jsonify({'error': 'Invalid email format'}), 400
            update_fields.append('email = ?')
            update_values.append(data['email'])
        
        if 'password' in data:
            if len(data['password']) < 6:
                return jsonify({'error': 'Password must be at least 6 characters'}), 400
            import hashlib
            hashed_password = hashlib.sha256(data['password'].encode()).hexdigest()
            update_fields.append('password = ?')
            update_values.append(hashed_password)
        
        if 'salary' in data:
            update_fields.append('salary = ?')
            update_values.append(data['salary'])
        
        if 'is_active' in data:
            update_fields.append('is_active = ?')
            update_values.append(data['is_active'])
        
        if update_fields:
            update_values.append(manager_id)
            query = f'UPDATE users SET {", ".join(update_fields)} WHERE id = ? AND role = "manager"'
            conn.execute(query, tuple(update_values))
            
            # Логируем действие
            log_activity(session['user_id'], 'update_manager', 
                        f'Обновлен менеджер ID: {manager_id}', 'user', manager_id)
            
            conn.commit()
        
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для удаления менеджера
@app.route('/api/managers/<int:manager_id>', methods=['DELETE'])
@require_auth
@require_role('admin')
@handle_errors
def delete_manager(manager_id):
    """Удаление менеджера (деактивация)"""
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET is_active = 0 WHERE id = ? AND role = "manager"', (manager_id,))
        
        # Логируем действие
        log_activity(session['user_id'], 'delete_manager', 
                    f'Деактивирован менеджер ID: {manager_id}', 'user', manager_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# ==================== МОДУЛЬ ГРАФИКА РАБОТЫ ====================

# API для получения графика работы пользователя
@app.route('/api/work-schedules/<int:user_id>')
@require_auth
@handle_errors
def get_work_schedule(user_id):
    """Получение графика работы пользователя"""
    # Пользователь может видеть свой график, админ - любой
    if session.get('user_role') != 'admin' and session['user_id'] != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    schedules = conn.execute('''
        SELECT * FROM work_schedules 
        WHERE user_id = ?
        ORDER BY day_of_week
    ''', (user_id,)).fetchall()
    conn.close()
    
    return jsonify([dict(schedule) for schedule in schedules])

# API для получения всех графиков работы (только для админа)
@app.route('/api/work-schedules')
@require_auth
@require_role('admin')
@handle_errors
def get_all_work_schedules():
    """Получение всех графиков работы (только админ)"""
    conn = get_db_connection()
    schedules = conn.execute('''
        SELECT ws.*, u.username, u.email, u.role
        FROM work_schedules ws
        JOIN users u ON ws.user_id = u.id
        ORDER BY u.username, ws.day_of_week
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(schedule) for schedule in schedules])

# API для создания/обновления графика работы (только админ)
@app.route('/api/work-schedules', methods=['POST', 'PUT'])
@require_auth
@require_role('admin')
@handle_errors
def save_work_schedule():
    """Создание или обновление графика работы (только админ)"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    user_id = data.get('user_id')
    day_of_week = data.get('day_of_week')
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    is_working_day = data.get('is_working_day', True)
    
    if user_id is None or day_of_week is None:
        return jsonify({'error': 'user_id and day_of_week are required'}), 400
    
    if is_working_day and (not start_time or not end_time):
        return jsonify({'error': 'start_time and end_time are required for working days'}), 400
    
    conn = get_db_connection()
    try:
        # Проверяем существование записи
        existing = conn.execute('''
            SELECT id FROM work_schedules 
            WHERE user_id = ? AND day_of_week = ?
        ''', (user_id, day_of_week)).fetchone()
        
        if existing:
            # Обновляем существующую запись
            conn.execute('''
                UPDATE work_schedules 
                SET start_time = ?, end_time = ?, is_working_day = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (start_time if is_working_day else None, 
                  end_time if is_working_day else None, 
                  is_working_day, existing['id']))
        else:
            # Создаем новую запись
            conn.execute('''
                INSERT INTO work_schedules (user_id, day_of_week, start_time, end_time, is_working_day)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, day_of_week, 
                  start_time if is_working_day else None, 
                  end_time if is_working_day else None, 
                  is_working_day))
        
        # Логируем действие
        log_activity(session['user_id'], 'update_work_schedule', 
                    f'Обновлен график работы для пользователя ID: {user_id}, день: {day_of_week}', 
                    'work_schedule', user_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для массового обновления графика работы (только админ)
@app.route('/api/work-schedules/bulk', methods=['PUT'])
@require_auth
@require_role('admin')
@handle_errors
def bulk_update_work_schedules():
    """Массовое обновление графика работы (только админ)"""
    data = request.get_json()
    
    if not data or 'schedules' not in data:
        return jsonify({'error': 'schedules array is required'}), 400
    
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400
    
    conn = get_db_connection()
    try:
        # Удаляем старые записи для этого пользователя
        conn.execute('DELETE FROM work_schedules WHERE user_id = ?', (user_id,))
        
        # Добавляем новые записи
        for schedule in data['schedules']:
            day_of_week = schedule.get('day_of_week')
            is_working_day = schedule.get('is_working_day', True)
            start_time = schedule.get('start_time') if is_working_day else None
            end_time = schedule.get('end_time') if is_working_day else None
            
            if day_of_week is not None:
                conn.execute('''
                    INSERT INTO work_schedules (user_id, day_of_week, start_time, end_time, is_working_day)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, day_of_week, start_time, end_time, is_working_day))
        
        # Логируем действие
        log_activity(session['user_id'], 'bulk_update_work_schedule', 
                    f'Массово обновлен график работы для пользователя ID: {user_id}', 
                    'work_schedule', user_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для получения менеджеров, назначенных на день недели
@app.route('/api/day-managers/<int:day_of_week>')
@require_auth
@handle_errors
def get_day_managers(day_of_week):
    """Получение менеджеров, назначенных на день недели"""
    conn = get_db_connection()
    managers = conn.execute('''
        SELECT dma.*, u.username, u.email, u.id as manager_id
        FROM day_manager_assignments dma
        JOIN users u ON dma.manager_id = u.id
        WHERE dma.day_of_week = ?
        ORDER BY dma.start_time, u.username
    ''', (day_of_week,)).fetchall()
    conn.close()
    
    return jsonify([dict(manager) for manager in managers])

# API для получения назначений менеджеров на дни недели (доступно для всех авторизованных)
@app.route('/api/day-managers/all')
@require_auth
@handle_errors
def get_all_day_managers_public():
    """Получение всех назначений менеджеров на дни недели (для просмотра)"""
    conn = get_db_connection()
    assignments = conn.execute('''
        SELECT dma.*, u.username, u.email, u.id as manager_id
        FROM day_manager_assignments dma
        JOIN users u ON dma.manager_id = u.id
        ORDER BY dma.day_of_week, dma.start_time, u.username
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(assignment) for assignment in assignments])

# API для получения всех назначений менеджеров на дни недели
@app.route('/api/day-managers')
@require_auth
@require_role('admin')
@handle_errors
def get_all_day_managers():
    """Получение всех назначений менеджеров на дни недели (только админ)"""
    conn = get_db_connection()
    assignments = conn.execute('''
        SELECT dma.*, u.username, u.email
        FROM day_manager_assignments dma
        JOIN users u ON dma.manager_id = u.id
        ORDER BY dma.day_of_week, dma.start_time, u.username
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(assignment) for assignment in assignments])

# API для назначения менеджера на день недели
@app.route('/api/day-managers', methods=['POST'])
@require_auth
@require_role('admin')
@handle_errors
def assign_day_manager():
    """Назначение менеджера на день недели (только админ)"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    day_of_week = data.get('day_of_week')
    manager_id = data.get('manager_id')
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    
    if day_of_week is None or manager_id is None:
        return jsonify({'error': 'day_of_week and manager_id are required'}), 400
    
    conn = get_db_connection()
    try:
        # Проверяем существование записи
        existing = conn.execute('''
            SELECT id FROM day_manager_assignments 
            WHERE day_of_week = ? AND manager_id = ?
        ''', (day_of_week, manager_id)).fetchone()
        
        if existing:
            # Обновляем существующую запись
            conn.execute('''
                UPDATE day_manager_assignments 
                SET start_time = ?, end_time = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (start_time, end_time, existing['id']))
        else:
            # Создаем новую запись
            conn.execute('''
                INSERT INTO day_manager_assignments (day_of_week, manager_id, start_time, end_time)
                VALUES (?, ?, ?, ?)
            ''', (day_of_week, manager_id, start_time, end_time))
        
        # Логируем действие
        log_activity(session['user_id'], 'assign_day_manager', 
                    f'Назначен менеджер ID: {manager_id} на день недели: {day_of_week}', 
                    'day_manager_assignment', manager_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для удаления назначения менеджера на день недели
@app.route('/api/day-managers/<int:assignment_id>', methods=['DELETE'])
@require_auth
@require_role('admin')
@handle_errors
def remove_day_manager(assignment_id):
    """Удаление назначения менеджера на день недели (только админ)"""
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM day_manager_assignments WHERE id = ?', (assignment_id,))
        
        # Логируем действие
        log_activity(session['user_id'], 'remove_day_manager', 
                    f'Удалено назначение менеджера ID: {assignment_id}', 
                    'day_manager_assignment', assignment_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для массового обновления назначений менеджеров на дни недели
@app.route('/api/day-managers/bulk', methods=['PUT'])
@require_auth
@require_role('admin')
@handle_errors
def bulk_update_day_managers():
    """Массовое обновление назначений менеджеров на дни недели (только админ)"""
    data = request.get_json()
    
    if not data or 'assignments' not in data:
        return jsonify({'error': 'assignments array is required'}), 400
    
    conn = get_db_connection()
    try:
        # Удаляем все старые назначения
        conn.execute('DELETE FROM day_manager_assignments')
        
        # Добавляем новые назначения
        for assignment in data['assignments']:
            day_of_week = assignment.get('day_of_week')
            manager_id = assignment.get('manager_id')
            start_time = assignment.get('start_time')
            end_time = assignment.get('end_time')
            
            if day_of_week is not None and manager_id is not None:
                conn.execute('''
                    INSERT INTO day_manager_assignments (day_of_week, manager_id, start_time, end_time)
                    VALUES (?, ?, ?, ?)
                ''', (day_of_week, manager_id, start_time, end_time))
        
        # Логируем действие
        log_activity(session['user_id'], 'bulk_update_day_managers', 
                    'Массово обновлены назначения менеджеров на дни недели', 
                    'day_manager_assignment', None)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# ==================== МОДУЛЬ СМЕН ====================

# API для открытия смены
@app.route('/api/shifts/start', methods=['POST'])
@require_auth
@require_role('manager')
@handle_errors
def start_shift():
    """Открытие смены менеджером"""
    from datetime import datetime, time
    
    conn = get_db_connection()
    manager_id = session['user_id']
    today = datetime.now().date()
    now = datetime.now()
    
    # Проверяем, не открыта ли уже смена на сегодня
    existing_shift = conn.execute('''
        SELECT * FROM shifts 
        WHERE manager_id = ? AND shift_date = ? AND status = "active"
    ''', (manager_id, today)).fetchone()
    
    if existing_shift:
        conn.close()
        return jsonify({'error': 'Shift already started today'}), 400
    
    # Проверяем опоздание (смена должна начаться до 10:00)
    shift_deadline = datetime.combine(today, time(10, 0))
    is_late = now > shift_deadline
    late_minutes = 0
    
    if is_late:
        late_minutes = int((now - shift_deadline).total_seconds() / 60)
    
    try:
        cursor = conn.execute('''
            INSERT INTO shifts (manager_id, shift_date, shift_start_time, is_late, late_minutes, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (manager_id, today, now, is_late, late_minutes, 'active'))
        shift_id = cursor.lastrowid
        
        # Если опоздание, создаем штраф
        if is_late:
            penalty_amount = 500  # Штраф за опоздание
            conn.execute('''
                INSERT INTO penalties (manager_id, shift_id, penalty_type, penalty_amount, reason, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (manager_id, shift_id, 'late_shift', penalty_amount, 
                  f'Опоздание на {late_minutes} минут', session.get('user_id')))
        
        # Логируем действие
        log_activity(manager_id, 'start_shift', 
                    f'Открыта смена (опоздание: {late_minutes} мин)' if is_late else 'Открыта смена',
                    'shift', shift_id, {'is_late': is_late, 'late_minutes': late_minutes})
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'shift_id': shift_id,
            'is_late': is_late,
            'late_minutes': late_minutes
        }), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для закрытия смены
@app.route('/api/shifts/end', methods=['POST'])
@require_auth
@require_role('manager')
@handle_errors
def end_shift():
    """Закрытие смены менеджером"""
    conn = get_db_connection()
    manager_id = session['user_id']
    today = datetime.now().date()
    now = datetime.now()
    
    try:
        shift = conn.execute('''
            SELECT * FROM shifts 
            WHERE manager_id = ? AND shift_date = ? AND status = "active"
        ''', (manager_id, today)).fetchone()
        
        if not shift:
            conn.close()
            return jsonify({'error': 'No active shift found'}), 404
        
        conn.execute('''
            UPDATE shifts 
            SET shift_end_time = ?, status = "completed", updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (now, shift['id']))
        
        # Логируем действие
        log_activity(manager_id, 'end_shift', 'Закрыта смена', 'shift', shift['id'])
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для получения текущей смены
@app.route('/api/shifts/current')
@require_auth
@require_role('manager')
@handle_errors
def get_current_shift():
    """Получение текущей активной смены"""
    conn = get_db_connection()
    manager_id = session['user_id']
    today = datetime.now().date()
    
    shift = conn.execute('''
        SELECT * FROM shifts 
        WHERE manager_id = ? AND shift_date = ? AND status = "active"
    ''', (manager_id, today)).fetchone()
    
    conn.close()
    
    if shift:
        return jsonify({'shift': dict(shift)})
    return jsonify({'shift': None})

# API для получения всех смен (админ)
@app.route('/api/shifts')
@require_auth
@handle_errors
def get_shifts():
    """Получение всех смен"""
    conn = get_db_connection()
    
    if session.get('user_role') == 'admin':
        shifts = conn.execute('''
            SELECT s.*, u.username as manager_name
            FROM shifts s
            JOIN users u ON s.manager_id = u.id
            ORDER BY s.shift_date DESC, s.shift_start_time DESC
        ''').fetchall()
    else:
        shifts = conn.execute('''
            SELECT * FROM shifts 
            WHERE manager_id = ?
            ORDER BY shift_date DESC, shift_start_time DESC
        ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return jsonify([dict(shift) for shift in shifts])

# ==================== МОДУЛЬ ШТРАФОВ ====================

# API для получения штрафов
@app.route('/api/penalties')
@require_auth
@handle_errors
def get_penalties():
    """Получение штрафов"""
    conn = get_db_connection()
    
    if session.get('user_role') == 'admin':
        penalties = conn.execute('''
            SELECT p.*, u.username as manager_name, u2.username as created_by_name
            FROM penalties p
            JOIN users u ON p.manager_id = u.id
            LEFT JOIN users u2 ON p.created_by = u2.id
            ORDER BY p.created_at DESC
        ''').fetchall()
    else:
        penalties = conn.execute('''
            SELECT p.*, u2.username as created_by_name
            FROM penalties p
            LEFT JOIN users u2 ON p.created_by = u2.id
            WHERE p.manager_id = ?
            ORDER BY p.created_at DESC
        ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return jsonify([dict(penalty) for penalty in penalties])

# API для создания штрафа (админ)
@app.route('/api/penalties', methods=['POST'])
@require_auth
@require_role('admin')
@handle_errors
def create_penalty():
    """Создание штрафа админом"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    manager_id = data.get('manager_id')
    penalty_type = data.get('penalty_type', 'other')
    penalty_amount = data.get('penalty_amount', 0)
    reason = data.get('reason', '')
    shift_id = data.get('shift_id')
    
    if not manager_id or not penalty_amount:
        return jsonify({'error': 'Manager ID and penalty amount are required'}), 400
    
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            INSERT INTO penalties (manager_id, shift_id, penalty_type, penalty_amount, reason, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (manager_id, shift_id, penalty_type, penalty_amount, reason, session['user_id']))
        penalty_id = cursor.lastrowid
        
        # Логируем действие
        log_activity(session['user_id'], 'create_penalty', 
                    f'Создан штраф: {penalty_amount} руб. для менеджера ID: {manager_id}',
                    'penalty', penalty_id, {'manager_id': manager_id, 'amount': penalty_amount})
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': penalty_id}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# ==================== МОДУЛЬ ЛОГОВ ДЕЙСТВИЙ ====================

# API для получения логов действий
@app.route('/api/activity-logs')
@require_auth
@require_role('admin')
@handle_errors
def get_activity_logs():
    """Получение логов действий (только админ)"""
    manager_id = request.args.get('manager_id', type=int)
    limit = request.args.get('limit', 100, type=int)
    
    conn = get_db_connection()
    
    if manager_id:
        logs = conn.execute('''
            SELECT al.*, u.username
            FROM activity_logs al
            JOIN users u ON al.user_id = u.id
            WHERE al.user_id = ?
            ORDER BY al.created_at DESC
            LIMIT ?
        ''', (manager_id, limit)).fetchall()
    else:
        logs = conn.execute('''
            SELECT al.*, u.username
            FROM activity_logs al
            JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT ?
        ''', (limit,)).fetchall()
    
    conn.close()
    return jsonify([dict(log) for log in logs])

# API для получения списка менеджеров (для фильтра)
@app.route('/api/managers/list')
@require_auth
@require_role('admin')
@handle_errors
def get_managers_list():
    """Получение списка менеджеров для фильтра"""
    conn = get_db_connection()
    managers = conn.execute('''
        SELECT id, username, email, is_active
        FROM users
        WHERE role = 'manager'
        ORDER BY username
    ''').fetchall()
    conn.close()
    return jsonify([dict(m) for m in managers])

# ==================== МОДУЛЬ ПУЛА ЧАТОВ ====================

# API для взятия чата из пула
@app.route('/api/chats/<int:chat_id>/take', methods=['POST'])
@require_auth
@require_role('manager')
@handle_errors
def take_chat_from_pool(chat_id):
    """Взять чат из пула"""
    conn = get_db_connection()
    manager_id = session['user_id']
    
    try:
        # Проверяем что чат в пуле
        chat = conn.execute('''
            SELECT assigned_manager_id FROM avito_chats WHERE id = ?
        ''', (chat_id,)).fetchone()
        
        if not chat:
            conn.close()
            return jsonify({'error': 'Chat not found'}), 404
        
        if chat['assigned_manager_id'] is not None:
            conn.close()
            return jsonify({'error': 'Chat is already assigned'}), 400
        
        # Назначаем чат менеджеру
        conn.execute('''
            UPDATE avito_chats 
            SET assigned_manager_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (manager_id, chat_id))
        
        # Логируем действие
        log_activity(manager_id, 'take_chat', 
                    f'Взят чат из пула ID: {chat_id}', 'chat', chat_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для возврата чата в пул
@app.route('/api/chats/<int:chat_id>/return', methods=['POST'])
@require_auth
@require_role('manager')
@handle_errors
def return_chat_to_pool(chat_id):
    """Вернуть чат в пул"""
    conn = get_db_connection()
    manager_id = session['user_id']
    
    try:
        # Проверяем что чат назначен этому менеджеру
        chat = conn.execute('''
            SELECT assigned_manager_id FROM avito_chats WHERE id = ?
        ''', (chat_id,)).fetchone()
        
        if not chat:
            conn.close()
            return jsonify({'error': 'Chat not found'}), 404
        
        if chat['assigned_manager_id'] != manager_id:
            conn.close()
            return jsonify({'error': 'Chat is not assigned to you'}), 403
        
        # Возвращаем чат в пул
        conn.execute('''
            UPDATE avito_chats 
            SET assigned_manager_id = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (chat_id,))
        
        # Логируем действие
        log_activity(manager_id, 'return_chat', 
                    f'Возвращен чат в пул ID: {chat_id}', 'chat', chat_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для переноса клиента по флагам доставки
@app.route('/api/deliveries/<int:delivery_id>/move', methods=['POST'])
@require_auth
@handle_errors
def move_delivery_status(delivery_id):
    """Перенос доставки на следующий статус"""
    data = request.get_json()
    new_status = data.get('status')
    
    if not new_status:
        return jsonify({'error': 'Status is required'}), 400
    
    # Новые статусы: в работе, свободно, закрыт, на доставку, отказался
    valid_statuses = ['in_work', 'free', 'closed', 'on_delivery', 'refused']
    if new_status not in valid_statuses:
        return jsonify({'error': 'Invalid status'}), 400
    
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE deliveries 
            SET delivery_status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (new_status, delivery_id))
        
        # Логируем действие
        delivery = conn.execute('SELECT chat_id FROM deliveries WHERE id = ?', (delivery_id,)).fetchone()
        if delivery:
            log_activity(session['user_id'], 'move_delivery', 
                        f'Перенесена доставка на статус: {new_status}', 'delivery', delivery_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# API для удаления доставки (только админ)
@app.route('/api/deliveries/<int:delivery_id>', methods=['DELETE'])
@require_auth
@require_role('admin')
@handle_errors
def delete_delivery(delivery_id):
    """Удаление доставки (только админ)"""
    conn = get_db_connection()
    try:
        delivery = conn.execute('SELECT * FROM deliveries WHERE id = ?', (delivery_id,)).fetchone()
        if not delivery:
            conn.close()
            return jsonify({'error': 'Delivery not found'}), 404
        
        conn.execute('DELETE FROM deliveries WHERE id = ?', (delivery_id,))
        
        log_activity(session['user_id'], 'delete_delivery', 
                    f'Удалена доставка ID: {delivery_id}', 'delivery', delivery_id)
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# Страница управления доставками (только админ)
@app.route('/deliveries/manage')
@require_auth
@require_role('admin')
def manage_deliveries_page():
    """Страница управления доставками для админа"""
    user = get_user_by_id(session['user_id'])
    return render_template('manage_deliveries.html', user=user)

# Запускаем сервер
if __name__ == '__main__':
    print("[START] Запускаем CRM систему...")
    print("[INFO] База данных: tbgsosat_crm.db")
    print("[INFO] Тестовые пользователи:")
    print("   Админ: admin@tbgsosat.com / admin123")
    print("   Менеджер: dannnnnbb@gmail.com / manager123")
    print("[INFO] Сервер доступен по адресу: http://localhost:5000")
    app.run(debug=True, port=5000)