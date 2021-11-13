#### Parser Content
```Java
{
Name = sophos-security-alert-1
  Conditions = [ """Event::Endpoint::Threat::""" ]
  
sophos-security-alert = {
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"(rt|when)":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"(n\/a|({alert_name}[^\:\"]{1,2000})(\:\s{0,100}({target}[^\"]{1,2000}))?)"""",
    """"name":\s{0,100}"(n\/a|({additional_info}[^"]{1,2000}))""",
    """"name":\s{0,100}"(n\/a|({alert_name}[^\:\"\']{1,2000}(\:\s{0,100}\'({target}[^\"\']{1,2000}))?\'))""",
    """"name":\s{0,100}"(n\/a|[^"]{0,2000}? at \'({additional_info}({malware_url}[^"\']{1,2000})))""",
    """"type":\s{0,100}"(n\/a|({alert_type}[^"]{1,2000}))""",
    """"dhost":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"(suser|source)":\s{0,100}"(n\/a|({user_fullname}[^"\\\(\),]{1,2000}))"""",
    """"(suser|source)":\s{0,100}"(n\/a|({user_lastname}[^",\s]{1,2000}),\s{0,100}({user_firstname}[^,"\s]{1,2000}))""",
    """"(suser|source)":\s{0,100}"(n\/a|(({domain}[^\\"]{1,2000})\\+)?({user}[^\\\s"]{1,2000}))"""",
    """"(suser|source)":\s{0,100}"(n\/a|({src_host}[\w\-.]{1,2000})\s{0,100}(\(({src_ip}[A-Fa-f:\d.]{1,2000})\))?)"""",
    """"id":\s{0,100}"({alert_id}[^"]{1,2000})""",
    """filePath":\s"({process}[^"]{1,2000}\\+({process_name}[^"]{1,2000}))""",
  
}
```