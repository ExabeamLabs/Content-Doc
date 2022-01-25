#### Parser Content
```Java
{
Name = s-azure-authorization-activity-3
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "cloud-admin-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """resourceProviderName": {"value": "Microsoft.Authorization""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"resourceProviderName":\s{0,100}\{[^\}]{0,2000}?"localizedValue":\s{0,100}"({service}[^"]{1,2000})"""",
    """"eventTimestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"operationName":\s{0,100}\{[^\}]{0,2000}?"localizedValue":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"caller":\s{0,100}"({user}[^"\s@]{1,2000})"""",
    """"caller":\s{0,100}"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})"""",
    """"httpRequest":\s{0,100}\{[^\}]{0,2000}?"clientIpAddress":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"tenantId":"({account_id}[^"]{1,2000})""",
    """"status": \{"value": "({outcome}[^"]{1,2000})""",
    """policyDefinitions\/({policy}[^"\/]{1,2000})""",
    """resourceId".+?policyAssignments\/({policy_assignment}[^"]{1,2000})""",
    """roleDefinitions\/({role}[^"]{1,2000})""",
    """resourceId".+?roleAssignments\/({role_assignment}[^"]{1,2000})""",
    """resourceId": ".+?Microsoft.({provider}\w+)\/\w+\/({object}[^"]{1,2000}).+?resourceType"""
    """resourceId": ".+?Microsoft.\w+.+?Microsoft.({provider}\w+)\/\w+\/({object}[^"]{1,2000}).+?resourceType""",
    """resourceGroupName": "({account_id}[^"]{1,2000})"""

  ]
}
```