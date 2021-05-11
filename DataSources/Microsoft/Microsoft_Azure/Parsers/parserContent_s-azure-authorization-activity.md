#### Parser Content
```Java
{
Name = s-azure-authorization-activity
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "cloud-admin-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """resourceProviderName":{"value":"Microsoft.Authorization""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"resourceProviderName":\s{0,100}\{[^\}]*?"localizedValue":\s{0,100}"({service}[^"]+)"""",
    """"eventTimestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"operationName":\s{0,100}\{[^\}]*?"localizedValue":\s{0,100}"({activity}[^"]+)"""",
    """"caller":\s{0,100}"({user}[^"\s@]+)"""",
    """"caller":\s{0,100}"({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"httpRequest":\s{0,100}\{[^\}]*?"clientIpAddress":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
    """"tenantId":"({account_id}[^"]+)""",
    """"status":\{"value":"({outcome}[^"]+)""",
    """policyDefinitions\/({policy}[^"\/]+)""",
    """resourceId".+?policyAssignments\/({policy_assignment}[^"]+)""",
    """roleDefinitions\/({role}[^"]+)""",
    """resourceId".+?roleAssignments\/({role_assignment}[^"]+)""",
    """resourceId":".+?Microsoft.({provider}\w+)\/\w+\/({object}[^"]+).+?resourceType"""
    """resourceId":".+?Microsoft.\w+.+?Microsoft.({provider}\w+)\/\w+\/({object}[^"]+).+?resourceType""",
    """resourceGroupName":"({account_id}[^"]+)"""

  ]
}
```