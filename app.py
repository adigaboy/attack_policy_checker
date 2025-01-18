import datetime
import json
import logging
import sys
import time
from dataclasses import dataclass
from enum import StrEnum, auto
from functools import lru_cache
from typing import Any, Dict


class PolicyTypes(StrEnum):
    ips=auto()
    protocols=auto()
    ports=auto()


class RolesVerdicts(StrEnum):
    CLEAN='CLEAN'
    SUSPICIOUS='SUSPICIOUS'


def read_attack_from_file():
    with open('inputs/attacks.csv', newline='') as file:
        file.readline()
        yield from file

def read_file_headers():
    with open('inputs/attacks.csv', newline='') as file:
        return file.readline()


@dataclass
class PortsScheme:
    start: int
    end: int


def read_policies() -> Dict[str, Any]:
    policies = []
    with open('inputs/policy.json', 'r') as fd:
        input_policies = json.loads(fd.read())
        for policy in input_policies:
            entered_policy = {}
            if PolicyTypes.protocols in policy:
                entered_policy[PolicyTypes.protocols] = policy[PolicyTypes.protocols][0]
            if PolicyTypes.ips in policy:
                entered_policy[PolicyTypes.ips] = policy[PolicyTypes.ips][0]
            if PolicyTypes.ports in policy:
                entered_policy[PolicyTypes.ports] = PortsScheme(**policy[PolicyTypes.ports][0])
            policies.append((entered_policy, policy['verdict']))
    return policies

class PolicyChecker:
    policy_match_counters = {
            PolicyTypes.ips: 0,
            PolicyTypes.protocols: 0,
            PolicyTypes.ports: 0,
            'None': 0
    }
    policy_verdict_to_connection_verdict = {
        'IGNORE': RolesVerdicts.CLEAN,
        'INSPECT': RolesVerdicts.SUSPICIOUS
    }

    def __init__(self, log_level):
        self.policy_types_and_checks = {
            PolicyTypes.ips: self.check_ips_policy,
            PolicyTypes.protocols: self._check_protocol_policy,
            PolicyTypes.ports: self._check_port_policy
        }
        self.all_policies = read_policies()

        self.logger = logging.getLogger()
        lh = logging.FileHandler('logs.log')
        self.logger.setLevel(log_level)
        self.logger.addHandler(lh)
        sh = logging.StreamHandler()
        sh.setLevel(log_level)
        self.logger.addHandler(sh)

    def check(self, attack: str):
        self.logger.debug(
            f'Checking attack {attack}'
        )
        verdict_sum = None
        for policy, verdict in self.all_policies:
            if PolicyTypes.ips in policy and PolicyTypes.ports in policy:
                # if policy have IPs and Ports need to check them together
                self.logger.debug('Checking both IP and Prot on same side')
                if self._check_ip_and_port_policy(attack, policy[PolicyTypes.ips], policy[PolicyTypes.ports]):
                    self.policy_match_counters[PolicyTypes.ips] += 1
                    self.policy_match_counters[PolicyTypes.ports] += 1
                    verdict_sum = self.policy_verdict_to_connection_verdict[verdict]
                    if verdict_sum == RolesVerdicts.CLEAN:
                        return verdict_sum
                if PolicyTypes.protocols in policy:
                    if self._check_protocol_policy(attack, policy[PolicyTypes.protocols]):
                        verdict_sum = self.policy_verdict_to_connection_verdict[verdict]
            else:
                # check policies 1 by 1
                self.logger.debug('Checking all policies')
                for policy_type, policy_checks in policy.items():
                    if self.policy_types_and_checks[policy_type](attack, policy_checks):
                        self.policy_match_counters[policy_type] += 1
                        verdict_sum = self.policy_verdict_to_connection_verdict[verdict]
                        if verdict_sum == RolesVerdicts.CLEAN:
                            return verdict_sum
        if verdict_sum is None:
            # didn't match any policy role
            self.policy_match_counters['None'] += 1
        return verdict_sum or RolesVerdicts.CLEAN

    def _check_ip_and_port_policy(self, attack: str, policy_cidr: str, policy_ports: PortsScheme) -> bool:
        attack = attack.split(',')
        self.logger.debug(f'Checking source ip & port')
        source_ip_check = self._check_ip(attack[1], policy_cidr)
        source_port_check = self._check_port(attack[2], policy_ports.start, policy_ports.end)
        if source_ip_check and source_port_check:
            return True
        self.logger.debug(f'Checking destination ip & port')
        dest_ip_check = self._check_ip(attack[3], policy_cidr)
        dest_port_check = self._check_port(attack[4], policy_ports.start, policy_ports.end)
        if dest_ip_check and dest_port_check:
            return True
        return False

    def check_ips_policy(self, attack: str, checked_ips: str) -> bool:
        attack = attack.split(',')
        source_ip_result = self._check_ip(attack[1], checked_ips)
        dest_ip_result = self._check_ip(attack[3], checked_ips)
        return source_ip_result or dest_ip_result

    @lru_cache(maxsize=1024)
    def _check_ip(self, ip: str, policy_cidr: str) -> bool:
        # do a bitwise compare for ips according to bit mask of CIDR
        self.logger.debug(f'IP check attack: {ip}, policy: {policy_cidr}')
        checked_ip, bits_locked = policy_cidr.split('/')
        bits_locked = int(bits_locked)
        ip = ip.split('.')
        checked_ip = checked_ip.split('.')
        if bits_locked == 32:
            return ip == checked_ip
        last_octet_checked = bits_locked // 8
        # compare full octets
        if ip[:last_octet_checked] != checked_ip[:last_octet_checked]:
            return False
        # compare last octet with bitwise shift
        ip = int(ip[last_octet_checked])
        checked_ip = int(checked_ip[last_octet_checked])
        return ip >> (8 - last_octet_checked) == checked_ip >> (8 - last_octet_checked)

    def _check_port_policy(self, attack: str, ports: PortsScheme) -> bool:
        attack = attack.split(',')
        source_port_result = self._check_port(attack[2], ports.start, ports.end)
        dest_port_result = self._check_port(attack[4], ports.start, ports.end)
        return source_port_result or dest_port_result

    @lru_cache(maxsize=5120)
    def _check_port(self, checked_port: str, ports_start: int, ports_end: int) -> bool:
        self.logger.debug(f'Port check attack: {checked_port}, policy port start: {ports_start}, port end: {ports_end}')
        if checked_port == '':
            return False
        return ports_start <= int(checked_port) <= ports_end

    def _check_protocol_policy(self, attack: str, protocols: str) -> bool:
        attack = attack.split(',')
        return self._protocol_check(attack[5], protocols)

    @lru_cache(maxsize=32)
    def _protocol_check(self, checked_protocol: str, policy_protocol: str) -> bool:
        self.logger.debug(f'Protocol check attack: {checked_protocol}, policy: {policy_protocol}')
        return checked_protocol == policy_protocol

    def print_policies_matches_counters(self) -> None:
        self.logger.info(
            f'Policies match counters: {self.policy_match_counters}',
        )

    def print_cache_info(self) -> None:
        self.logger.info(
            f'Ports check cache info: {self._check_port.cache_info()}',
        )
        self.logger.info(
            f'IPs check cache info: {self._check_ip.cache_info()}',
        )
        self.logger.info(
            f'Protocols check cache info: {self._protocol_check.cache_info()}',
        )

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
