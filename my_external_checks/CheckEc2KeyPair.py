from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class CheckEc2KeyPair(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EC2 does not have SSH keypair enabled "
        id = "CUSTOM_AWS_EC2_1"
        supported_resources = ['aws_instance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self,conf,entity_type):
        #print(conf)
        
        if 'key_name' in conf: #this means ec2 has keypair attached to it  
                #vpc_id = conf['vpc_id']
            return CheckResult.FAILED
        else:
            return CheckResult.PASSED
    
        

scanner = CheckEc2KeyPair()