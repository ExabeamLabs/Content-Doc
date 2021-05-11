#### Parser Content
```Java
{
Name = sophos-web-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Event::Endpoint::Web""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"location":"({host}[^"]+)""",
    """"(rt|when)":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"(n\/a|({alert_name}[^\:\"\']+(\:\s{0,100}\'({target}[^\"\']+))?\'))""",
    """"name":\s{0,100}"'({target}[^']+)'\s{1,100}({alert_name}[^"']+)\s""",
    """"name":\s{0,100}"({alert_name}[^"']+)\sto '({target}[^']+)'\s{1,100}""",
    """"name":\s{0,100}"'({malware_url}[^"\'\s]+)'\s{1,100}blocked due to""",
    """"name":\s{0,100}"[^"]*?block to\s{1,100}'({malware_url}[^"\'\s]+)'""",
    """"name":\s{0,100}"(n\/a|[^"]*? at \'({additional_info}({malware_url}[^"\']+)))""",
    """"name":\s{0,100}"({additional_info}[^}]+?)("\}|","\w+":)""",
    """"type":\s{0,100}"({alert_type}[^"]+)""",
    """"dhost":\s{0,100}"({src_host}[^"]+)""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)""",
    """"(suser|source)":\s{0,100}"(n\/a|(({domain}[^\\"]+)\\+)?({user_fullname}[^\\\(\)\s",]+\s{1,100}[^\\\(\)",]+))"""",
    """"(suser|source)":\s{0,100}"(n\/a|({user_lastname}[^",\s]+),\s{0,100}({user_firstname}[^,"\s]+))""",
    """"(suser|source)":\s{0,100}"(n\/a|(({domain}[^\\"]+)\\+)?({user}[^\\\s"]+))"""",
    """"(suser|source)":\s{0,100}"(n\/a|({src_host}[\w\-.]+)\s{0,100}(\(({src_ip}[A-Fa-f:\d.]+)\))?)"""",
    """"id":\s{0,100}"({alert_id}[^"]+)""",
  ]
}
```