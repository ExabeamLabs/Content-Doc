#### Parser Content
```Java
{
Name = cef-netskope-alert-compromise
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"Compromised Credential"""", """destinationServiceName=Netskope""", """|security-threat-detected|""", """"type":"breach"""" ]
 Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """"_id":"({alert_id}[^"]{1,2000})""",
    """"category":"(n\/a|({threat_category}[^"]{1,2000}))""",
    """"alert_type"{1,20}:"{1,20}({alert_name}[^"]{1,2000})""",
    """"hostname":"({src_host}[^"]{1,2000})""",
    """security-threat-detected\|({alert_severity}\d{1,100})""",
    """"alert_name":"({additional_info}[^"]{1,2000})""",
    """"type":"({alert_type}[^"]{1,2000})"""
  ]
}
```