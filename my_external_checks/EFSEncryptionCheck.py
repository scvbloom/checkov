from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class EFSEncryptionCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EFS is encrypted"
        id = "CUSTOM_AWS_EFS_1"
        supported_resources = ['aws_efs_file_system']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self,conf,entity_type):
        print(conf)
        
        if 'encrypted' in conf: #this means efs has encrypted option
            if conf.get('encrypted',True):
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        else:
            return CheckResult.FAILED
    
        

scanner = EFSEncryptionCheck()