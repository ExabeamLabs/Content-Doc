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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"location":"({host}[^"]{1,2000})""",
    """"(rt|when)":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"(n\/a|({alert_name}[^\:\"\']{1,2000}(\:\s{0,100}\'({target}[^\"\']{1,2000}))?\'))""",
    """"name":\s{0,100}"'({target}[^']{1,2000})'\s{1,100}({alert_name}[^"']{1,2000})\s""",
    """"name":\s{0,100}"({alert_name}[^"']{1,2000})\sto '({target}[^']{1,2000})'\s{1,100}""",
    """"name":\s{0,100}"'({malware_url}[^"\'\s]{1,2000})'\s{1,100}blocked due to""",
    """"name":\s{0,100}"[^"]{0,2000}?block to\s{1,100}'({malware_url}[^"\'\s]{1,2000})'""",
    """"name":\s{0,100}"(n\/a|[^"]{0,2000}? at \'({additional_info}({malware_url}[^"\']{1,2000})))""",
    """"name":\s{0,100}"({additional_info}[^}]{1,2000}?)("\}|","\w+":)""",
    """"type":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"dhost":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"(suser|source)":\s{0,100}"(n\/a|(({domain}[^\\"]{1,2000})\\+)?({user_fullname}[^\\\(\)\s",]{1,2000}\s{1,100}[^\\\(\)",]{1,2000}))"""",
    """"(suser|source)":\s{0,100}"(n\/a|({user_lastname}[^",\s]{1,2000}),\s{0,100}({user_firstname}[^,"\s]{1,2000}))""",
    """"(suser|source)":\s{0,100}"(n\/a|(({domain}[^\\"]{1,2000})\\+)?({user}[^\\\s"]{1,2000}))"""",
    """"(suser|source)":\s{0,100}"(n\/a|({src_host}[\w\-.]{1,2000})\s{0,100}(\(({src_ip}[A-Fa-f:\d.]{1,2000})\))?)"""",
    """"id":\s{0,100}"({alert_id}[^"]{1,2000})""",
  ]
}
```