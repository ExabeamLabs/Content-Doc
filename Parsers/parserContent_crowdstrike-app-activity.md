#### Parser Content
```Java
{
Name = crowdstrike-app-activity
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """"eventType":""", """"UserActivityAuditEvent"""", """"OperationName":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventCreationTime":\s*({time}\d+)""",
    """"UserId":\s*"({user_email}[^"@]+@[^"@]+)"""",
    """"UserId":\s*"({user}[^"@]+)"""",
    """"UserIp":\s*"({src_ip}[^"]+)""",
    """"ServiceName":\s*"({resource}[^"]+)""",
    """({app}CrowdStrike)""",
    """"OperationName":\s*"({activity}[^",]+)""",
    """"AuditKeyValues":\[({additional_info}.+?)\]""",
    """"AuditKeyValues":[^\]]+?"Value(String)?":"({object}.*?[^\\])"(,|\})""",
  ]
}
```