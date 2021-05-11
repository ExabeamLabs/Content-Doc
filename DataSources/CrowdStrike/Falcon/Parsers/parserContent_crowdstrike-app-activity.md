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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"UserId":\s{0,100}"({user_email}[^"@]+@[^"@]+)"""",
    """"UserId":\s{0,100}"({user}[^"@]+)"""",
    """"UserIp":\s{0,100}"({src_ip}[^"]+)""",
    """"ServiceName":\s{0,100}"({resource}[^"]+)""",
    """({app}CrowdStrike)""",
    """"OperationName":\s{0,100}"({activity}[^",]+)""",
    """"AuditKeyValues":\[({additional_info}.+?)\]""",
    """"AuditKeyValues":[^\]]+?"Value(String)?":"({object}.*?[^\\])"(,|\})""",
  ]
}
```