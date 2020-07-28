#### Parser Content
```Java
{
Name = sophos-security-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Event::Endpoint::WebControlViolation"""", """"User bypassed category block """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"rt":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s*"({alert_name}[^'"]+) to '({malware_url}[^'"]+)""",
    """"name":\s*"({additional_info}[^"]+)""",
    """"type":\s*"({alert_type}[^"]+)""",
    """"dhost":\s*"({src_host}[^"]+)""",
    """"severity":\s*"({alert_severity}[^"]+)""",
    """"(suser|source)":\s*"(n\/a|(({domain}[^\\"]+)\\+)?({user_fullname}[^\\\(\)\s",]+\s+[^\\\(\)",]+))"""",
    """"(suser|source)":\s*"(n\/a|({user_lastname}[^",\\\s]+),\s*({user_firstname}[^,"\\\s]+))""",
    """"(suser|source)":\s*"(?:n\/a|({user}[^",\\\s]+))"""",
    """"(suser|source)":\s*"(({domain}[^\\",]+)\\+)?({user}[^",\\\/\s]+)"""",
    """"id":\s*"({alert_id}[^"]+)""",
  ]
}
```