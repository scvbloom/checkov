from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.type_forcers import force_list
from checkov.common.util.type_forcers import force_int

class RDSSGCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS has Security Group associated with it"
        id = "CUSTOM_AWS_RDS_1"
        supported_resources = ['aws_rds_cluster','aws_db_instance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self,conf,entity_type):
        print(conf)
        
        if 'vpc_security_group_ids' in conf: 
            sg_conf= conf['vpc_security_group_ids']
            for sg_id in sg_conf:
                sg_ids = force_list(sg_id)
            if len(sg_ids) > 0 and "sg" in sg_ids:

                return CheckResult.PASSED
            else:
                return CheckResult.FAILED
        else:
            return CheckResult.FAILED
    
        

scanner = RDSSGCheck()