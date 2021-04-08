from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list
from checkov.common.util.type_forcers import force_int

class RDSPortCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS does not have default port enabled"
        id = "CUSTOM_AWS_RDS_2"
        supported_resources = ['aws_rds_cluster','aws_db_instance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self,conf,entity_type):
        print(conf)
        
        if 'port' in conf: #this means rds has port option 
            
            #port_conf = conf['port']
            if conf.get('port',[]):
                port_conf = conf['port']
                for port in port_conf:
                    #port = force_list(ports)
                    if (port == "1433" or port == "3306" or port == "1521"):
                        return CheckResult.FAILED
                    return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        else:
            return CheckResult.FAILED
        # else:
        #     return CheckResult.FAILED
        

scanner = RDSPortCheck()