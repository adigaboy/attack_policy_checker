import datetime
import logging
import sys
import time

from app.policy_checker import PolicyChecker
from app.schemes import RolesVerdicts


def read_attack_from_file():
    with open('inputs/attacks.csv', newline='') as file:
        file.readline()
        yield from file

def read_file_headers():
    with open('inputs/attacks.csv', newline='') as file:
        return file.readline()



def main(debug_level):
    suspicious_attacks = []
    counters = {
        RolesVerdicts.SUSPICIOUS: 0,
        RolesVerdicts.CLEAN: 0
    }
    start_time = time.time()
    policy_checker = PolicyChecker(debug_level)
    logger = logging.getLogger()
    logger.info(
        '--------------------------------------'
    )
    logger.info(
        f'Starting a new run: {datetime.datetime.now()}'
    )
    with open('suspicious_connections.csv', 'w') as csv_file:
        headers = read_file_headers()
        csv_file.write(headers)
        for attack in read_attack_from_file():
            try:
                result = policy_checker.check(attack.replace('"', '').rstrip('\n'))
            except Exception as err:
                logger.error(
                    f'Error while checking {attack}, details: {err}'
                )
                continue
            counters[result] += 1
            if result == RolesVerdicts.SUSPICIOUS:
                csv_file.write(attack)
                suspicious_attacks.append(attack)
    logger.info(
        f'Connection counters: {counters}'
    )
    policy_checker.print_policies_matches_counters()
    policy_checker.print_cache_info()
    end_time = time.time()
    logger.info(
        f'App run time: {round(end_time - start_time, 2)} secs.'
    )
    print()

if __name__ == '__main__':
    debug_level = logging.INFO
    if '-d' in sys.argv:
        debug_level = sys.argv[2]
    main(debug_level)
