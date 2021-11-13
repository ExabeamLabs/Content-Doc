#### Parser Content
```Java
{
Name = crowdstrike-app-activity-7
  Conditions = [ """"eventType":""", """"AuthActivityAuditEvent"""", """"OperationName":""", """"grantUserRoles"""" ]
  Fields =  ${CrowdStrikeParserTemplates.crowdstrike-app-activity.Fields} [
    """"eventCreationTime":({time}\d{1,100})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"UserId":\s{0,100}"({user_email}[^"@]{1,2000}@[^"@]{1,2000})"""",
    """"UserId":\s{0,100}"({user}[^"@]{1,2000})"""",
    """"UserIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"ServiceName":\s{0,100}"({app}[^"]{1,2000})""",
    """"Success":\s{0,100}({outcome}[^",]{1,2000})""",
    """"OperationName":"({event_name}[^"]{1,2000})"""
]

crowdstrike-app-activity = {
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"timestamp":"({time}\d{1,100})""",
    """"OperationName":"({activity}[^"]{1,2000})""",
    """"event_simpleName":"({activity}[^"]{1,2000})""",
    """"aip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """suser=(system|({user}[^\s]{1,2000}))""",
    """"Success":({outcome}true|false)""",
    """"UserId":"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))""", 
  
}
```