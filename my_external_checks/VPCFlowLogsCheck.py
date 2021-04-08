from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list
from checkov.common.util.type_forcers import force_int

class VPCFlowLogsCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure VPC has flow logs enabled"
        id = "CUSTOM_AWS_VPC_1"
        supported_resources = ['aws_flow_log']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self,conf,entity_type):
        print(conf)
        
        if 'vpc_id' in conf: #this means terraform has flow logs  
            
            return CheckResult.PASSED
        else:
            return CheckResult.FAILED
    
        

scanner = VPCFlowLogsCheck()