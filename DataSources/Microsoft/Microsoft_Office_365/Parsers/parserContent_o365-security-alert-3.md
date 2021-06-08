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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"event-name":"({event_name}[^"]{1,2000})"""",
    """"riskType":"({alert_name}[^"]{1,2000})""",
    """"ipAddress":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"userDisplayName":"({user_fullname}[^"]{1,2000})"""",
    """"userPrincipalName":"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """"severity":({alert_severity}\d{1,100})""",
    """"requestId":"({alert_id}[^"]{1,2000})"""",
    """"is-violating":({outcome}[^,]{1,2000})""",
    """"riskEventTypes":\["({alert_name}[^"]{1,2000})"""",
  ]
  DupFields = ["alert_name->alert_type"]
}
```