#### Parser Content
```Java
{
Name = s-duo-auth-json
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "authentication-attempt"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"new_enrollment"""",""""ip"""",""""result""""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"device":\s{0,100}"{0,20}(null\}?|({host}[\w\-.]{1,2000}))"""",
    """"ip"\s{0,100}:\s{0,100}"({src_ip}[^"]{1,2000})"""",
    """"username"\s{0,100}:\s{0,100}"(?:({domain}[^\\"]{1,2000})\\)?({user}[^"]{1,2000})"""",
    """"factor"\s{0,100}:\s{0,100}"(?:n\/a|({auth_method}[^"]{1,2000}))"""",
    """"os"\s{0,100}:\s{0,100}"({os}[^"]{1,2000})"""",
    """"os_version"\s{0,100}:\s{0,100}"({os_version}[^"]{1,2000})"""",
    """"browser"\s{0,100}:\s{0,100}"({browser}[^"]{1,2000})"""",
    """"browser_version"\s{0,100}:\s{0,100}"({browser_version}[^"]{1,2000})"""",
    """"result"\s{0,100}:\s{0,100}"({outcome}[^"]{1,2000})"""",
    """"reason"\s{0,100}:\s{0,100}"({failure_reason}[^"]{1,2000})"""",
    """"new_enrollment"\s{0,100}:\s{0,100}({new_enrollment}true|false)""",
    """"{0,20}integration"{0,20}:\s{0,100}"{0,20}({service}[^"]{1,2000})"""
  ]


}
```