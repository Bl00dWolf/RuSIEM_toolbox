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
          f'4) Задать IP RuSIEM системы (по умолчанию 127.0.0.1)\n'
          f'5) Задать ключ API (по умолчанию не задан)\n'
          f'6) Задать данные для SSH (логин, пароль, пароль от sudo)\n'
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
        req_search_eps = requests.get(f'https://{settings['ip_addr']}/api/v1/system/searchEps', verify=False,
                                      params=request_params)
        req_eps = requests.get(f'https://{settings['ip_addr']}/api/v1/system/eps', verify=False, params=request_params)
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
                req_search_eps = requests.get(f'https://{settings['ip_addr']}/api/v1/system/searchEps', verify=False,
                                              params=request_params)
                req_eps = requests.get(f'https://{settings['ip_addr']}/api/v1/system/eps', verify=False,
                                       params=request_params)
                writer_csv.writerow([datetime.now(), req_search_eps.text, req_eps.text])
                print(
                    f'{datetime.now()} Текущее EPS (searchEps): {req_search_eps.text:>6}; EPS (eps): {req_eps.text:>6}')
                time.sleep(settings['time_to_sleep'])

    # Если запись в файл не выбрана, то выводим текущие значения c заданным интервалом ожидания.
    while 1:
        req_search_eps = requests.get(f'https://{settings['ip_addr']}/api/v1/system/searchEps', verify=False,
                                      params=request_params)
        req_eps = requests.get(f'https://{settings['ip_addr']}/api/v1/system/eps', verify=False, params=request_params)
        print(f'{datetime.now()} Текущее EPS (searchEps): {req_search_eps.text:>6}; EPS (eps): {req_eps.text:>6}')
        time.sleep(settings['time_to_sleep'])


# Создание и загрузка настроек JSON.
def settings_file() -> None:
    global settings
    if not os.path.isfile('RuSIEM_toolbox_settings.json'):
        print(f'Файла конфигурации не существует, создаем:\n'
              f'{os.getcwd()}\\RuSIEM_toolbox_settings.json')
        with open('RuSIEM_toolbox_settings.json', 'w', encoding='utf-8') as file:
            settings = {'api_key': 'NO_API_KEY', 'ip_addr': '127.0.0.1', 'time_to_sleep': 5, 'ssh_login': 'None',
                        'ssh_password': 'None', 'ssh_sudo_pass': '', 'toolbox_version': '0.3'}
            json.dump(settings, file, indent=4, ensure_ascii=True)
    else:
        with open('RuSIEM_toolbox_settings.json', 'r', encoding='utf-8') as file:
            settings = json.load(file)

    # print(settings['ip_addr'], settings['api_key'], settings['time_to_sleep'])


# Сохранение новых параметров настроек
def save_settings(param, value) -> None:
    with open('RuSIEM_toolbox_settings.json', 'w', encoding='utf-8') as file:
        global settings
        settings[param] = value
        json.dump(settings, file, indent=4, ensure_ascii=True)


# Сохранение инцидента и его событий в файл
def save_incident(num: int):
    request_params = {'_api_key': settings['api_key']}
    request_params_limit = {'_api_key': settings['api_key'], 'limit': 999}
    req_inc = requests.get(f'https://{settings['ip_addr']}/api/v1/incidents/{num}/fullinfo', verify=False,
                           params=request_params)
    req_events = requests.get(f'https://{settings['ip_addr']}/api/v1/events/incident/{num}', verify=False,
                              params=request_params_limit)

    with open(f'incident_{num}.json', 'w', encoding='utf-8') as file:
        json.dump(json.loads(req_inc.text), file, indent=4, ensure_ascii=True)
    with open(f'events_of_incident_{num}.json', 'w', encoding='utf-8') as file:
        json.dump(json.loads(req_events.text), file, indent=4, ensure_ascii=True)
    print(f'Инцидент сохранен в файл:\n{os.getcwd()}\\incident_{num}.json\n'
          f'События инцидента сохранены в файл:\n{os.getcwd()}\\events_of_incident_{num}.json')


def show_rusiem_version() -> None | int:
    config = Config(overrides={'sudo': {'password': settings['ssh_sudo_pass']}})
    with Connection(settings['ip_addr'], port=22, user=settings['ssh_login'],
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
        try:
            print('\nВерсии компонентов RuSIEM:')
            res = conn.run('dpkg -l | grep rusiem', hide=True, encoding='utf-8')
            print(res.stdout.strip())
            res = conn.run('dpkg -l | grep elastic', hide=True, encoding='utf-8')
            print(res.stdout.strip())
            res = conn.run('dpkg -l | grep redis', hide=True, encoding='utf-8')
            print(res.stdout.strip())
            res = conn.run('dpkg -l | grep clickhouse', hide=True, encoding='utf-8')
            print(res.stdout.strip())
            res = conn.run('dpkg -l | grep postgre', hide=True, encoding='utf-8')
            print(res.stdout.strip())
        except Exception as err:
            print(f'Не удалось получить версию компонентов русием\n')

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
    with Connection(settings['ip_addr'], port=22, user=settings['ssh_login'],
                    connect_kwargs={'password': settings['ssh_password']}, config=config) as conn:

        # Проверяем коннект к серверу
        try:
            conn.run('pwd', hide=True)
        except Exception as err:
            print(f'Не удалось подключится к серверу {settings['ip_addr']}'
                  f'\nПроверьте корректность данных для подключения.')
            return -1

        logs_files = ['/var/www/html/app/storage/logs/user_actions.log', '']
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
            case 4:  # Задать IP RuSIEM системы (по умолчанию 127.0.0.1)
                value = input('Введите IP адрес СИЕМ системы (например 17.12.3.7):\n')
                save_settings('ip_addr', value)
            case 5:  # Задать ключ API (по умолчанию не задан)
                value = input('Введите API ключ:\n')
                save_settings('api_key', value)
            case 6:  # Задать данные для SSH (логин, пароль, пароль от sudo)
                ssh_login = input('Введите логин от SSH к серверу СИЕМ:\n')
                ssh_pass = input('Введите пароль от SSH:\n')
                ssh_sudo_pass = input('Введите пароль от sudo:\n')
                save_settings('ssh_login', ssh_login)
                save_settings('ssh_password', ssh_pass)
                save_settings('ssh_sudo_pass', ssh_sudo_pass)
            case 7:  # Выгрузить инцидент и события
                save_incident(int(input('Введите номер инцидента: \n')))
            case 8:  # Показать версии компонентов RuSIEM
                show_rusiem_version()
            case 9:  # Скачать логи
                pass
            case 0:  # Выход
                return
            case _:
                print('Такого пункта меню нет')
        time.sleep(5)
        main()


    main()
