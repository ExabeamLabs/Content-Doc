#### Parser Content
```Java
{
Name = s-azure-app-activity
  Conditions = [ """"eventTimestamp":""", """"caller":""", """"resourceProviderName":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"resourceProviderName":\s*\{[^\}]*?"localizedValue":\s*"({resource}[^"]+)"""",
    """"eventTimestamp":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"operationName":\s*\{[^\}]*?"localizedValue":\s*"({activity}[^"]+)"""",
    """"caller":\s*"({user}[^"\s@]+)"""",
    """"caller":\s*"({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
    """"httpRequest":\s*\{[^\}]*?"clientIpAddress":\s*"({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```