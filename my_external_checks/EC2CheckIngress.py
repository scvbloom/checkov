from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list
from checkov.common.util.type_forcers import force_int



class CheckEC2Ingress(BaseResourceCheck):
    def __init__(self):
        name = "Ensure no Security group rule has 0.0.0.0"
        id = "CUSTOM_AWS_SG_1"
        supported_resources = ['aws_security_group','aws_security_group_rule']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf, entity_type):
        # if conf.get("ingress",[]):
        #     ingress_rule = conf["ingress"]
        #     violation = "0.0.0.0/0"
        #     if violation in ingress_rule:
        #         return CheckResult.FAILED
        #     else:
        #         return CheckResult.PASSED

        if 'ingress' in conf:  # This means it's an SG resource with ingress block(s)
            ingress_conf = conf['ingress']
            for ingress_rule in ingress_conf:
                ingress_rules = force_list(ingress_rule)
                for rule in ingress_rules:
                    if isinstance(rule, dict):
                        if self.contains_violation(rule):
                            self.evaluated_keys = [
                                f'ingress/[{ingress_conf.index(ingress_rule)}]/cidr_blocks',
                                f'ingress/[{ingress_conf.index(ingress_rule)}]/ipv6_cidr_blocks',
                            ]
                            return CheckResult.FAILED

            return CheckResult.PASSED

        if 'type' in conf:  # This means it's an SG_rule resource.
            type = force_list(conf['type'])[0]
            if type == 'ingress':
                self.evaluated_keys = ['cidr_blocks', 'ipv6_cidr_blocks']
                if self.contains_violation(conf):
                    return CheckResult.FAILED
                return CheckResult.PASSED
            return CheckResult.UNKNOWN

        # The result for an SG with no ingress block
        return CheckResult.PASSED

    def contains_violation(self, conf):
        
        cidr_blocks = force_list(conf.get('cidr_blocks', [[]])[0])
        if "0.0.0.0/0" in cidr_blocks:
            return True
        ipv6_cidr_blocks = conf.get('ipv6_cidr_blocks', [])
        if len(ipv6_cidr_blocks) > 0 and any(ip in ['::/0', '0000:0000:0000:0000:0000:0000:0000:0000/0'] for ip in ipv6_cidr_blocks[0]):
            return True


scanner = CheckEC2Ingress()

    