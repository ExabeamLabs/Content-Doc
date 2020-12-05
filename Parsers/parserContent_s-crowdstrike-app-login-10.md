#### Parser Content
```Java
{
Name = s-crowdstrike-app-login-10
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"EventType":""", """"Event_AuthActivityAuditEvent"""", """"OperationName":""", """"saml2Assert"""" ]
  Fields =  ${CrowdStrikeParserTemplates.s-crowdstrike-app-login.Fields} [
    """"timestamp":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"OperationName":\s*"({event_name}[^"]+)"""
 ]
}
```