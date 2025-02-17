
from functools import lru_cache
import ipaddress
import json
import logging
from typing import Any, Dict

from app.schemes import PolicyTypes, PortsScheme, RolesVerdicts



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
        self.policy_types_and_check_functions = {
            PolicyTypes.ips: self.check_ips_policy,
            PolicyTypes.protocols: self._check_protocol_policy,
            PolicyTypes.ports: self._check_port_policy,
            PolicyTypes.ip_and_port: self._check_ip_port_policy
        }
        self.read_policies()
        self.setup_logger(log_level)

    def setup_logger(self, log_level):
        self.logger = logging.getLogger()
        lh = logging.FileHandler('logs.log')
        self.logger.setLevel(log_level)
        self.logger.addHandler(lh)
        sh = logging.StreamHandler()
        sh.setLevel(log_level)
        self.logger.addHandler(sh)

    def read_policies(self) -> None:
        self.all_policies = []
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
                self.all_policies.append((entered_policy, policy['verdict']))

    def check(self, attack: str):
        self.logger.debug(
            f'Checking attack {attack}'
        )
        verdict_sum = None
        for policy, verdict in self.all_policies:
            if PolicyTypes.ips in policy and PolicyTypes.ports in policy:
                # if policy have IPs and Ports need to check them together
                self.logger.debug('Checking both IP and Prot on same side')
                if self.policy_types_and_check_functions[PolicyTypes.ip_and_port](attack, policy[PolicyTypes.ips], policy[PolicyTypes.ports]):
                    self.policy_match_counters[PolicyTypes.ips] += 1
                    self.policy_match_counters[PolicyTypes.ports] += 1
                    verdict_sum = self.policy_verdict_to_connection_verdict[verdict]
                    if verdict_sum == RolesVerdicts.CLEAN:
                        return verdict_sum
                if PolicyTypes.protocols in policy:
                    if self.policy_types_and_check_functions[PolicyTypes.protocols](attack, policy[PolicyTypes.protocols]):
                        verdict_sum = self.policy_verdict_to_connection_verdict[verdict]
            else:
                # check policies 1 by 1
                self.logger.debug('Checking all policies')
                for policy_type, policy_checks in policy.items():
                    if self.policy_types_and_check_functions[policy_type](attack, policy_checks):
                        self.policy_match_counters[policy_type] += 1
                        verdict_sum = self.policy_verdict_to_connection_verdict[verdict]
                        if verdict_sum == RolesVerdicts.CLEAN:
                            return verdict_sum
        if verdict_sum is None:
            # didn't match any policy role
            self.policy_match_counters['None'] += 1
        return verdict_sum or RolesVerdicts.CLEAN

    def _check_ip_port_policy(self, attack: str, policy_cidr: str, policy_ports: PortsScheme) -> bool:
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
        return ipaddress.ip_address(ip) in ipaddress.ip_network(policy_cidr, strict=False)

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
