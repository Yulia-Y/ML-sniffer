# import psutil
# import pyshark
# import sys
# import Connection
# import TcpReconstruction


# Устанавливаем кодировку консоли на UTF-8
# sys.stdout.reconfigure(encoding='utf-8')

# def packet_callback(packet):
#     # В этой функции можно обрабатывать каждый перехваченный пакет
#     print(packet)

# # Получаем список всех сетевых интерфейсов
# interfaces = psutil.net_if_addrs()

# # Выводим список интерфейсов для выбора
# print("Список доступных сетевых интерфейсов:")
# for i, interface in enumerate(interfaces.keys()):
#     print(f"{i}: {interface}")

# # Запрашиваем у пользователя выбор интерфейса
# choice = int(input("Выберите номер интерфейса для захвата пакетов: "))
# interface_names = list(interfaces.keys())
# if choice < 0 or choice >= len(interface_names):
#     print("Недопустимый выбор интерфейса.")
#     exit()

# # Выбираем сетевой интерфейс для захвата пакетов
# capture_dev = interface_names[choice]

# # Создаем объект LiveCapture для захвата пакетов с выбранного сетевого интерфейса
# capture = pyshark.LiveCapture(interface=capture_dev)

# # Применяем callback-функцию для каждого перехваченного пакета
# capture.apply_on_packets(packet_callback)


# connections = {}

# # Пример добавления элементов в словарь
# connection = Connection.Connection("192.168.34.56", 1234, "192.168.34.67", 5678)
# tcp_reconstruction = TcpReconstruction.TcpReconstruction()
# tcp_reconstruction.tcp_reconstruction("C:\\sniffer\\sessions\\file")
# dir = "C:\\sniffer\\sessions\\file"
# connections[connection] = tcp_reconstruction
# count = 5
# print(f"{dir}\\file_{count}")
# # Пример обращения к элементам словаря
# for conn, reconstr in connections.items():
#     print(f"Connection: {conn.source_ip}:{conn.source_port} -> {conn.destination_ip}:{conn.destination_port}")


# import argparse

# # Создаем парсер аргументов
# parser = argparse.ArgumentParser(description='Пример программы с несколькими флагами')

# # Добавляем флаги
# parser.add_argument('-f', '--flag', action='store_true', help='Пример первого флага')
# parser.add_argument('-n', '--number', type=int, help='Пример второго флага')

# # Парсим аргументы
# args = parser.parse_args()

# # Проверяем наличие флагов и выводим сообщения
# if args.flag:
#     print('Первый флаг был установлен!')
# else:
#     print('Первый флаг не был установлен.')

# if args.number is not None:
#     print('Второй флаг был установлен с числом:', args.number)
# else:
#     print('Второй флаг не был установлен.')

import platform

# Получение списка всех поддерживаемых платформ
supported_platforms = platform._supported_platform[:]
print("Supported platforms:", supported_platforms)

