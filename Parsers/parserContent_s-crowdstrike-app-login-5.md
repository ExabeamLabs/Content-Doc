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
```