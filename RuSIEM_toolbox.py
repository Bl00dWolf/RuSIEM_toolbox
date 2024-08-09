import requests
import urllib3
from datetime import datetime
import time
import json
import csv
import os

# Убираем предупреждение о самоподписанном сертификате СИЕМ
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

settings: dict = {}
today_date = datetime.now().date().strftime("%Y_%m_%d")

eps_file_exists = False
if os.path.isfile(f'current_eps_{today_date}.csv'):
    eps_file_exists = True


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
          f'{'-' * 20}\n'
          f'6) Выгрузить инцидент и события\n'
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


def settings_file() -> None:
    global settings
    if not os.path.isfile('RuSIEM_toolbox_settings.json'):
        print(f'Файла конфигурации не существует, создаем:\n'
              f'{os.getcwd()}\\RuSIEM_toolbox_settings.json')
        with open('RuSIEM_toolbox_settings.json', 'w', encoding='utf-8') as file:
            settings = {'api_key': 'NO_API_KEY', 'ip_addr': '127.0.0.1', 'time_to_sleep': 5, 'toolbox_version': '0.2'}
            json.dump(settings, file, indent=4, ensure_ascii=True)
    else:
        with open('RuSIEM_toolbox_settings.json', 'r', encoding='utf-8') as file:
            settings = json.load(file)

    # print(settings['ip_addr'], settings['api_key'], settings['time_to_sleep'])


def save_settings(param, value) -> None:
    with open('RuSIEM_toolbox_settings.json', 'w', encoding='utf-8') as file:
        global settings
        settings[param] = value
        json.dump(settings, file, indent=4, ensure_ascii=True)


def save_incident(num: int):
    request_params = {'_api_key': settings['api_key']}
    req_inc = requests.get(f'https://{settings['ip_addr']}/api/v1/incidents/{num}/fullinfo', verify=False,
                           params=request_params)
    print(req_inc.text)
    with open(f'incident_{num}', 'w', encoding='utf-8') as file:
        json.dump(req_inc.text, file, indent=4, ensure_ascii=True)


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
            case 6:  # Выгрузить инцидент и события
                save_incident(int(input('Введите номер инцидента: \n')))
            case 0:  # Выход
                return
            case _:
                print('Такого пункта меню нет')
        main()


    main()
