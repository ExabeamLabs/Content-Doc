#### Parser Content
```Java
{
Name = s-crowdstrike-app-login-5
  Conditions = [ """"eventType":""", """"RemoteResponseSessionStartEvent"""", """UserName""" ]
  Fields = ${CrowdStrikeParserTemplates.s-crowdstrike-app-login.Fields} [
    """"UserName":\s*"({user_email}[^"@]+@[^"@]+)"""",
    """"UserName":\s*"({user}[^"@]+)"""",
    """"HostnameField":\s*"({host}[^"@]+)"""",
    """destinationServiceName=({app}.+?)\s(\w+=|$)"""
  ]
}
${CrowdStrikeParserTemplates.s-crowdstrike-app-login}{
  Name = s-crowdstrike-app-login-6
  Conditions = [ """"eventType":""", """"AuthActivityAuditEvent"""", """"OperationName":""", """"CreateAPIClient"""" ]
  Fields =  ${CrowdStrikeParserTemplates.s-crowdstrike-app-login.Fields} [
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