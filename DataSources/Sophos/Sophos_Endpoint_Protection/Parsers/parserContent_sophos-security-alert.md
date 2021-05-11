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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"rt":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"({alert_name}[^'"]+) to '({malware_url}[^'"]+)""",
    """"name":\s{0,100}"({additional_info}[^"]+)""",
    """"type":\s{0,100}"({alert_type}[^"]+)""",
    """"dhost":\s{0,100}"({src_host}[^"]+)""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)""",
    """"(suser|source)":\s{0,100}"(n\/a|(({domain}[^\\"]+)\\+)?({user_fullname}[^\\\(\)\s",]+\s{1,100}[^\\\(\)",]+))"""",
    """"(suser|source)":\s{0,100}"(n\/a|({user_lastname}[^",\\\s]+),\s{0,100}({user_firstname}[^,"\\\s]+))""",
    """"(suser|source)":\s{0,100}"(?:n\/a|({user}[^",\\\s]+))"""",
    """"(suser|source)":\s{0,100}"(({domain}[^\\",]+)\\+)?({user}[^",\\\/\s]+)"""",
    """"id":\s{0,100}"({alert_id}[^"]+)""",
  ]
}
```