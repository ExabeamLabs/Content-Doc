#### Parser Content
```Java
{
Name = o365-security-alert-3
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""src-application-name":"Office 365"""","""event-name":"security-threat-detected"""",""""src-event-id"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s""",
    """exabeam_host=({host}[^\s]+)""",
    """"event-name":"({event_name}[^"]+)"""",
    """"riskType":"({alert_name}[^"]+)""",
    """"ipAddress":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"userDisplayName":"({user}[^"]+)"""",
    """"userPrincipalName":"({user_email}[^@]+@({email_domain}[^"]+))"""",
    """"severity":({alert_severity}\d+)""",
    """"requestId":"({alert_id}[^"]+)"""",
    """"is-violating":({outcome}[^,]+)""",
    """"riskEventTypes":\["({alert_name}[^"]+)"""",
  ]
  DupFields = ["alert_name->alert_type"]
}
```