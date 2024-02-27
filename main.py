#!/home/an/Dev/work_update_cert/venv/bin/python3
import socket
import subprocess
import logging
from datetime import datetime

import OpenSSL
from OpenSSL.SSL import Connection, Context, SSL3_VERSION, TLSv1_2_METHOD


UPDATE_PERIOD = 90
logging.basicConfig(level=logging.INFO, filename='main.py.log', filemode='w')


def run(domain, owner):
    """
    Запускает скрипт создания/обновления сертификата.
    Пишет вывод скриптов / ошибки скриптов в файлы.
    """
    result_skript = subprocess.run(
        ['./1.sh', f'{domain}', f'{owner}'],
        stderr=subprocess.PIPE, stdout=subprocess.PIPE
    )
    result_copy = subprocess.run(
        ['./copy_patch_letsencrypt_hestia', f'{domain}', f'{owner}'],
        stderr=subprocess.PIPE, stdout=subprocess.PIPE
    )
    with open(domain, 'w') as out, open(f'err_{domain}', 'w') as err:
        out.write(result_skript.stdout.decode('utf-8'))
        out.write(result_copy.stdout.decode('utf-8'))
        err.write(result_skript.stderr.decode('utf-8'))
        err.write(result_copy.stderr.decode('utf-8'))

    if result_skript.stderr is None or result_copy.stderr is None:
        logging.warning(
            f'Смотри ошибки в файле err_{domain}.'
        )


def sert_domain_info(domain, owner):
    """Получение информации о сертификате."""
    cert_info = {}

    try:
        try:
            ssl_connection_setting = Context(SSL3_VERSION)
        except ValueError:
            ssl_connection_setting = Context(TLSv1_2_METHOD)
        # Таймаут сеанса
        ssl_connection_setting.set_timeout(5)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((domain, 443))
            connect = Connection(ssl_connection_setting, sock)
            # Отдаю имя сервера для приветствия клиента
            connect.set_tlsext_host_name(str.encode(domain))
            # Отработка рукопожатий
            connect.set_connect_state()
            connect.do_handshake()

            # Получить сертификат домена
            cert = connect.get_peer_certificate()

            if cert.has_expired():
                logging.warning(
                    f'Срок действия сертификата для {domain} истек!'
                )
                logging.info(
                    f'Запускаю обновление сертификата для {domain}.'
                )
                run(domain, owner)
            else:
                date_domain = datetime.strptime(
                    str(cert.get_notAfter().decode('utf-8')), '%Y%m%d%H%M%SZ'
                )
                delta = date_domain - datetime.now()
                if delta.days < UPDATE_PERIOD:
                    logging.info(
                        f'Запускаю обновление сертификата для {domain}.'
                    )
                    run(domain, owner)
                else:
                    logging.info(
                        f'{domain} не требует обновление сертификата.'
                    )
            connect.shutdown()
            sock.close()
            return cert_info
    except (
        TypeError, ConnectionRefusedError,
        socket.gaierror, OSError, OpenSSL.SSL.Error
    ):
        logging.error(
            f'Соединение с {domain} не удалось'
        )
        return cert_info


with open('domain_list.txt', 'r') as file:
    for line in file:
        domain_owner = line.split()
        domain = domain_owner[0]
        owner = domain_owner[1]
        # Получаю информацию о статусе домена
        sert_domain_info(domain, owner)
