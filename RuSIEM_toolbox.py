import requests
import urllib3
from datetime import datetime
import time
import json
import csv
import os
from fabric import Connection, Config

# Убираем предупреждение о самоподписанном сертификате СИЕМ
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

settings: dict = {}
today_date = datetime.now().date().strftime("%Y_%m_%d")

eps_file_exists = False
if os.path.isfile(f'current_eps_{today_date}.csv'):
    eps_file_exists = True


# Вывод основного меню и опций
def hello_message() -> None:
    print(f'\n{'-' * 20}\n'
          f'Добро пожаловать в RuSIEM Toolbox версии {settings['toolbox_version']}!\n'
          f'{'-' * 20}\n'
          f'1) Отобразить текущий показатель EPS в консоли\n'
          f'2) Отобразить и записать статистику EPS в CSV файл\n'
          f'3) Установить интервал считывания ESP (по умолчанию раз в 5 секунд)\n'
          f'{'-' * 20}\n'
          f'4) Задать IP RuSIEM системы (по умолчанию 127.0.0.1) и порт (по умолчанию 443)\n'
          f'5) Задать ключ API (по умолчанию не задан)\n'
          f'6) Задать данные для SSH (логин, пароль, пароль от sudo, порт)\n'
          f'{'-' * 20}\n'
          f'7) Выгрузить инцидент и события\n'
          f'8) Показать версии компонентов SIEM и ТТХ сервера\n'
          f'9) Скачать логи (laravel, analytics, lsinput и тд)\n'
          f'{'-' * 20}\n'
          f'0) Выход'
          )


def get_eps(*, to_file: bool = False) -> None | str:
    request_params = {'_api_key': settings['api_key']}
    # Проверяем можем ли мы получить данные о текущем значении EPS или что-то не так.
    try:
        req_search_eps = requests.get(f'https://{settings['ip_addr']}:{settings['web_port']}/api/v1/system/searchEps',
                                      verify=False,
                                      params=request_params)
        req_eps = requests.get(f'https://{settings['ip_addr']}:{settings['web_port']}/api/v1/system/eps', verify=False,
                               params=request_params)
    except Exception as err:
        print('Не удалось установить соединение с SIEM, проверьте верность IP адреса')
        print(err)
        return 'Failed'

    if req_search_eps.status_code == 401:
        print('Введен неверный ключ API или IP адрес')
        return 'Failed'

    # Если выбрана запись в файл
    if to_file:
        # Если файл не существует - создаем его и вписываем название поле вверху.
        if not eps_file_exists:
            with open(f'current_eps_{today_date}.csv', 'w', newline='', encoding='utf-8') as file:
                writer_csv = csv.writer(file)
                writer_csv.writerow(['DATE', 'EPS (Search EPS)', 'EPS (eps)'])

        # Запись в файл даты и текущих EPS
        with open(f'current_eps_{today_date}.csv', 'a', newline='', encoding='utf-8') as file:
            writer_csv = csv.writer(file)
            print(f'Запись в файл начата:\n{os.getcwd()}\\current_eps_{today_date}.csv')

            # Бесконечно с заданным интервалом запрашиваем и пишем данные.
            while 1:
                req_search_eps = requests.get(
                    f'https://{settings['ip_addr']}:{settings['web_port']}/api/v1/system/searchEps', verify=False,
                    params=request_params)
                req_eps = requests.get(f'https://{settings['ip_addr']}:{settings['web_port']}/api/v1/system/eps',
                                       verify=False,
                                       params=request_params)
                writer_csv.writerow([datetime.now(), req_search_eps.text, req_eps.text])
                print(
                    f'{datetime.now()} Текущее EPS (searchEps): {req_search_eps.text:>6}; EPS (eps): {req_eps.text:>6}')
                time.sleep(settings['time_to_sleep'])

    # Если запись в файл не выбрана, то выводим текущие значения c заданным интервалом ожидания.
    while 1:
        req_search_eps = requests.get(f'https://{settings['ip_addr']}:{settings['web_port']}/api/v1/system/searchEps',
                                      verify=False,
                                      params=request_params)
        req_eps = requests.get(f'https://{settings['ip_addr']}:{settings['web_port']}/api/v1/system/eps', verify=False,
                               params=request_params)
        print(f'{datetime.now()} Текущее EPS (searchEps): {req_search_eps.text:>6}; EPS (eps): {req_eps.text:>6}')
        time.sleep(settings['time_to_sleep'])


# Сохранение новых параметров настроек
def save_settings(param, value) -> None:
    with open('RuSIEM_toolbox_settings.json', 'w', encoding='utf-8') as file:
        global settings
        settings[param] = value
        json.dump(settings, file, indent=4, ensure_ascii=True)


# Создание и загрузка настроек JSON.
def settings_file() -> None:
    logs_files = ['/var/www/html/app/storage/logs/user_actions.log', '/var/log/redis/redis-server.log',
                  '/var/log/postgresql/postgresql-10-main.log', '/opt/rusiem/lsinput/log/*.log',
                  '/opt/rusiem/lsinput/log/*.log.1*', '/opt/rusiem/lsfilter/log/*.log',
                  '/opt/rusiem/lsfilter/log/*.log.1*', '/opt/rusiem/lselastic/log/*.log',
                  '/opt/rusiem/lselastic/log/*.log.1*', '/opt/rusiem/frs_server/log/*.log',
                  '/opt/rusiem/frs_server/log/*.log.1*', '/var/www/html/app/storage/logs/*.log',
                  '/var/log/elasticsearch/rusiem.log', '/var/log/asset-rest-api/asset-api.log',
                  '/var/log/rusiem-processing/app.log', '/var/log/clickhouse-server/clickhouse-server.log',
                  '/var/log/clickhouse-server/clickhouse-server.err.log', '/var/mail/root']

    global settings
    settings = {'api_key': 'NO_API_KEY', 'ip_addr': '127.0.0.1', 'time_to_sleep': 5, 'ssh_login': 'None',
                'ssh_password': 'None', 'ssh_sudo_pass': '', 'toolbox_version': 0.3, 'ssh_port': 22,
                'web_port': 443, 'log_files': logs_files}

    if not os.path.isfile('RuSIEM_toolbox_settings.json'):
        print(f'Файла конфигурации не существует, создаем:\n'
              f'{os.getcwd()}\\RuSIEM_toolbox_settings.json')
        with open('RuSIEM_toolbox_settings.json', 'w', encoding='utf-8') as file:
            json.dump(settings, file, indent=4, ensure_ascii=True)
    else:
        with open('RuSIEM_toolbox_settings.json', 'r', encoding='utf-8') as file:
            settings_from_file = json.load(file)
            for key, value in settings.items():
                if key not in settings_from_file:
                    settings_from_file[key] = value
                    save_settings(key, value)
            settings = settings_from_file

    # print(settings['ip_addr'], settings['api_key'], settings['time_to_sleep'])


# Сохранение инцидента и его событий в файл
def save_incident(num: int):
    request_params = {'_api_key': settings['api_key']}
    request_params_limit = {'_api_key': settings['api_key'], 'limit': 999}
    req_inc = requests.get(f'https://{settings['ip_addr']}:{settings['web_port']}/api/v1/incidents/{num}/fullinfo',
                           verify=False,
                           params=request_params)
    req_events = requests.get(f'https://{settings['ip_addr']}:{settings['web_port']}/api/v1/events/incident/{num}',
                              verify=False,
                              params=request_params_limit)

    with open(f'incident_{num}.json', 'w', encoding='utf-8') as file:
        json.dump(json.loads(req_inc.text), file, indent=4, ensure_ascii=True)
    with open(f'events_of_incident_{num}.json', 'w', encoding='utf-8') as file:
        json.dump(json.loads(req_events.text), file, indent=4, ensure_ascii=True)
    print(f'Инцидент сохранен в файл:\n{os.getcwd()}\\incident_{num}.json\n'
          f'События инцидента сохранены в файл:\n{os.getcwd()}\\events_of_incident_{num}.json')


def show_rusiem_version() -> None | int:
    config = Config(overrides={'sudo': {'password': settings['ssh_sudo_pass']}})

    with Connection(settings['ip_addr'], port=settings['ssh_port'], user=settings['ssh_login'],
                    connect_kwargs={'password': settings['ssh_password']},
                    config=config) as conn:

        # Проверяем коннект к серверу
        try:
            conn.run('pwd', hide=True)
        except Exception as err:
            print(f'Не удалось подключится к серверу {settings['ip_addr']}'
                  f'\nПроверьте корректность данных для подключения.')
            return -1

        # Получаем версии ТТХ сервера:
        try:
            print('\nТТХ компонентов сервера:')
            res = conn.run('cat /etc/os-release; free -h; lsblk; lscpu; df -h', hide=True, encoding='utf-8')
            print(res.stdout.strip())
        except Exception as err:
            print(f'Не удалось получить ТТХ компонентов сервера\n')

        # Получаем версии пакетов через dpkg
        # TODO возможно стоит объединить в цикл один
        print('\nВерсии компонентов RuSIEM:')
        try:
            res = conn.run('dpkg -l | grep rusiem', hide=True, encoding='utf-8')
            print(res.stdout.strip())
        except Exception as err:
            print(
                f'Не удалось получить версию всех компонентов РуСием\nЕсли это машина с Elastic отдельная или без RuSIEM то это нормально.\n')

        try:
            res = conn.run('dpkg -l | grep elastic', hide=True, encoding='utf-8')
            print(res.stdout.strip())
        except Exception as err:
            print(f'Не удалось получить версию всех ElasticSearch\nЕсли установка не AIO, то это нормально.\n')

        try:
            res = conn.run('dpkg -l | grep redis', hide=True, encoding='utf-8')
            print(res.stdout.strip())
        except Exception as err:
            print(f'Не удалось получить версию Redis\nЕсли установка не AIO или без аналитики то это нормально.\n')

        try:
            res = conn.run('dpkg -l | grep clickhouse', hide=True, encoding='utf-8')
            print(res.stdout.strip())
        except Exception as err:
            print(f'Не удалось получить версию ClickHouse\nЕсли установка не AIO, то возможно это нормально.\n')

        try:
            res = conn.run('dpkg -l | grep postgre', hide=True, encoding='utf-8')
            print(res.stdout.strip())
        except Exception as err:
            print(f'Не удалось получить версию postgre sql\nЕсли установка не AIO, то возможно это нормально.\n')

        # Получаем версии cлужб
        services = ['lsinput', 'frs_server', 'lsfilter', 'lselastic']
        for service in services:
            try:
                print(f'\nВерсия службы {service}:')
                res = conn.run(f'/opt/rusiem/{service}/bin/{service} -v', hide=True, encoding='utf-8')
                print(res.stdout.strip())
            except Exception as err:
                print(f'Не удалось получить версию службы {service}. Возможно ее нет на сервере.\n')


def get_logs() -> None | int:
    config = Config(overrides={'sudo': {'password': settings['ssh_sudo_pass']}})

    with Connection(settings['ip_addr'], port=settings['ssh_port'], user=settings['ssh_login'],
                    connect_kwargs={'password': settings['ssh_password']}, config=config) as conn:

        # Проверяем коннект к серверу
        try:
            conn.run('pwd', hide=True)
        except Exception as err:
            print(f'Не удалось подключится к серверу {settings['ip_addr']}'
                  f'\nПроверьте корректность данных для подключения.')
            return -1

        conn.sudo(f'rm -rf /tmp/rusiem_tolboox_{today_date}', hide='stderr')
        conn.run(f'mkdir /tmp/rusiem_tolboox_{today_date}', hide='stderr')
        for log_file in settings['log_files']:
            try:
                conn.sudo(f'cp {log_file} /tmp/rusiem_tolboox_{today_date}/', hide='stderr')
            except:
                print(f'Файл {log_file} не найден, пропускаем.')
        conn.sudo(f'chmod 777 /tmp/rusiem_tolboox_{today_date}/*', hide='stderr')
        print(f'Создаем архив с логами, ждите.')
        conn.run(f'tar -czvf /tmp/rusiem_tolboox_{today_date}/logs.tar.gz /tmp/rusiem_tolboox_{today_date}/*',
                 hide=True)
        print(f'Скачиваем созданный архив, ждите.')
        conn.get(f'/tmp/rusiem_tolboox_{today_date}/logs.tar.gz')
        print(f'Архив сохранен в:\n{os.getcwd()}\\logs.tar.gz')
        conn.sudo(f'rm -rf /tmp/rusiem_tolboox_{today_date}', hide='stderr')
        # conn.sudo('cp /var/lib/clickhouse/uuid /tmp/toolbox_uuid', hide='stderr')
        # conn.sudo('chmod 777 /tmp/toolbox_uuid', hide='stderr')
        # conn.get('/tmp/toolbox_uuid')
        # conn.sudo('rm -rf /tmp/toolbox_uuid', hide='stderr')


if __name__ == '__main__':
    def main() -> None:
        settings_file()
        hello_message()

        user_selection: int = int(input('Введите пункт меню\n'))
        match user_selection:
            case 1:  # Отобразить текущий показатель EPS в консоли
                get_eps()
            case 2:  # Отобразить и записать статистику EPS в CSV файл
                get_eps(to_file=True)
            case 3:  # Установить интервал считывания ESP (по умолчанию раз в 5 секунд)
                value = int(input('Введите интервал в секундах между опросом значения EPS:\n'))
                save_settings('time_to_sleep', value)
            case 4:  # Задать IP RuSIEM системы (по умолчанию 127.0.0.1) и порт (по умолчанию 443)
                value = input('Введите IP адрес СИЕМ системы (например 17.12.3.7):\n')
                save_settings('ip_addr', value)
                value = int(input('Введите ПОРТ адрес СИЕМ системы (например 443 если обычный HTTPS):\n'))
                save_settings('web_port', value)
            case 5:  # Задать ключ API (по умолчанию не задан)
                value = input('Введите API ключ:\n')
                save_settings('api_key', value)
            case 6:  # Задать данные для SSH (логин, пароль, пароль от sudo, порт)
                ssh_login = input('Введите логин от SSH к серверу СИЕМ:\n')
                ssh_pass = input('Введите пароль от SSH:\n')
                ssh_sudo_pass = input('Введите пароль от sudo:\n')
                ssh_port = int(input('Введите порт SSH (обычно 22):\n'))
                save_settings('ssh_login', ssh_login)
                save_settings('ssh_password', ssh_pass)
                save_settings('ssh_sudo_pass', ssh_sudo_pass)
                save_settings('ssh_port', ssh_port)
            case 7:  # Выгрузить инцидент и события
                save_incident(int(input('Введите номер инцидента: \n')))
            case 8:  # Показать версии компонентов RuSIEM
                show_rusiem_version()
            case 9:  # Скачать логи
                get_logs()
            case 0:  # Выход
                return
            case _:
                print('Такого пункта меню нет')
        time.sleep(5)
        main()


    main()
