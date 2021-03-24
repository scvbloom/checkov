from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class VPCFlowLogsCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure VPC has flow logs enabled"
        id = "CUSTOM_AWS_VPC_1"
        supported_resources = ['aws_vpc','aws_flow_log']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self,conf,entity_type):
        print(conf)
        if 'cidr_block' in conf: #this means tf has VPC created in it 
            #vpc_id = conf.get['aws_vpc']
            if 'vpc_id' in conf: #this means terraform has flow logs  
                #vpc_id = conf['vpc_id']
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        return CheckResult.UNKNOWN
        

scanner = VPCFlowLogsCheck()