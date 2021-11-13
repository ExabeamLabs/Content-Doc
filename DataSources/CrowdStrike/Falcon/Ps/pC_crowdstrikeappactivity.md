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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"UserId":\s{0,100}"({user_email}[^"@]{1,2000}@[^"@]{1,2000})"""",
    """"UserId":\s{0,100}"({user}[^"@]{1,2000})"""",
    """"UserIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"ServiceName":\s{0,100}"({resource}[^"]{1,2000})""",
    """({app}CrowdStrike)""",
    """"OperationName":\s{0,100}"({activity}[^",]{1,2000})""",
    """"AuditKeyValues":\[({additional_info}.+?)\]""",
    """"AuditKeyValues":[^\]]{1,2000}?((_name")|(_id")|(Id"+)),"ValueString":"({object}[^"]{1,2000}?)\s{0,100}"(,|\})""", 
  ]


}
```