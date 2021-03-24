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
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"location":"({host}[^"]+)""",
    """"(rt|when)":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s*"(n\/a|({alert_name}[^\:\"\']+(\:\s*\'({target}[^\"\']+))?\'))""",
    """"name":\s*"'({target}[^']+)'\s+({alert_name}[^"']+)\s""",
    """"name":\s*"({alert_name}[^"']+)\sto '({target}[^']+)'\s+""",
    """"name":\s*"'({malware_url}[^"\'\s]+)'\s+blocked due to""",
    """"name":\s*"[^"]*?block to\s+'({malware_url}[^"\'\s]+)'""",
    """"name":\s*"(n\/a|[^"]*? at \'({additional_info}({malware_url}[^"\']+)))""",
    """"name":\s*"({additional_info}[^}]+?)("\}|","\w+":)""",
    """"type":\s*"({alert_type}[^"]+)""",
    """"dhost":\s*"({src_host}[^"]+)""",
    """"severity":\s*"({alert_severity}[^"]+)""",
    """"(suser|source)":\s*"(n\/a|(({domain}[^\\"]+)\\+)?({user_fullname}[^\\\(\)\s",]+\s+[^\\\(\)",]+))"""",
    """"(suser|source)":\s*"(n\/a|({user_lastname}[^",\s]+),\s*({user_firstname}[^,"\s]+))""",
    """"(suser|source)":\s*"(n\/a|(({domain}[^\\"]+)\\+)?({user}[^\\\s"]+))"""",
    """"(suser|source)":\s*"(n\/a|({src_host}[\w\-.]+)\s*(\(({src_ip}[A-Fa-f:\d.]+)\))?)"""",
    """"id":\s*"({alert_id}[^"]+)""",
  ]
}
```