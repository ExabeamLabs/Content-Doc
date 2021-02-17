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
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"resourceProviderName":\s*\{[^\}]*?"localizedValue":\s*"({service}[^"]+)"""",
    """"eventTimestamp":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"operationName":\s*\{[^\}]*?"localizedValue":\s*"({activity}[^"]+)"""",
    """"caller":\s*"({user}[^"\s@]+)"""",
    """"caller":\s*"({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"httpRequest":\s*\{[^\}]*?"clientIpAddress":\s*"({src_ip}[a-fA-F\d.:]+)""",
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