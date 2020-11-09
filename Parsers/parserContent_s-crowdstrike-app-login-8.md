#### Parser Content
```Java
{
Name = s-crowdstrike-app-login-8
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"  
  Conditions = [ """"event-name":""", """"audit-event"""", """"OperationName":"twoFactorAuthenticate"""" ]
  Fields =  ${CrowdStrikeParserTemplates.s-crowdstrike-app-login.Fields} [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"OperationName":"({event_name}[^"]+)"""
 ]
}
```