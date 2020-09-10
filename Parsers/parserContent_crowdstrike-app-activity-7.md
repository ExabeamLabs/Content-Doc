#### Parser Content
```Java
{
Name = crowdstrike-app-activity-7
  Conditions = [ """"eventType":""", """"AuthActivityAuditEvent"""", """"OperationName":""", """"grantUserRoles"""" ]
  Fields =  ${CrowdStrikeParserTemplates.crowdstrike-app-activity.Fields} [
    """"eventCreationTime":({time}\d+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventCreationTime":\s*({time}\d+)""",
    """"UserId":\s*"({user_email}[^"@]+@[^"@]+)"""",
    """"UserId":\s*"({user}[^"@]+)"""",
    """"UserIp":\s*"({src_ip}[^"]+)""",
    """"ServiceName":\s*"({app}[^"]+)""",
    """"Success":\s*({outcome}[^",]+)""",
    """"OperationName":"({event_name}[^"]+)"""
]
}
```