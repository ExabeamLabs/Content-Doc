#### Parser Content
```Java
{
Name = netskope-security-alert-1
  Vendor = Netskope
  Product = Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"alert_type":"Compromised Credential"""", """"alert":"yes"""", """"src-application-name":"Netskope"""", """"type":"breach"""", """"event-name":"security-threat-detected"""" ]
  Fields = [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000}\.[^"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """"_id":"({alert_id}[^"]{1,2000})""",
    """"category":"(n\/a|({threat_category}[^"]{1,2000}))""",
    """"alert_type":"({alert_name}[^"]{1,2000})"""",
    """"severity":({alert_severity}\d{1,2})""",
    """"alert_name":"({additional_info}[^"]{1,2000})""",
    """"type":"({alert_type}[^"]{1,2000})""",
    """"breach_description":"({additional_info}[^"]{1,2000})"""",
    """"target-users":\[\{"user-email":"({target_user_email}[^"@]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})""""
  ]


}
```