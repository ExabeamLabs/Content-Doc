#### Parser Content
```Java
{
Name = s-duo-auth-json
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "authentication-attempt"
  TimeFormat = "epoch_sec"
  Conditions = [ """"new_enrollment"""",""""ip"""",""""result""""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"host":\s{0,20}"({host}[^"]{1,2000})"""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """"device":\s{0,100}"{0,20}(null\}?|({device}[^",]{1,2000}))"""",
    """"{1,20}ip"{1,20}:\s"{1,20}(0.0.0.0|({src_ip}[a-fA-F:\.\d]{1,2000}))"""",
    """"username"\s{0,100}:\s{0,100}"(?:({domain}[^\\"]{1,2000})\\)?({user}[^"]{1,2000})"""",
    """"factor"\s{0,100}:\s{0,100}"(?:n\/a|({auth_method}[^"]{1,2000}))"""",
    """"os"\s{0,100}:\s{0,100}"({os}[^"]{1,2000})"""",
    """"os_version"\s{0,100}:\s{0,100}"({os_version}[^"]{1,2000})"""",
    """"browser"\s{0,100}:\s{0,100}"({browser}[^"]{1,2000})"""",
    """"browser_version"\s{0,100}:\s{0,100}"({browser_version}[^"]{1,2000})"""",
    """"result"\s{0,100}:\s{0,100}"({outcome}[^"]{1,2000})"""",
    """"reason"\s{0,100}:\s{0,100}"({failure_reason}[^"]{1,2000})"""",
    """"new_enrollment"\s{0,100}:\s{0,100}({new_enrollment}true|false)""",
    """"{0,20}integration"{0,20}:\s{0,100}"{0,20}({service}[^"]{1,2000})""",
    """"email":\s{0,20}"({user_email}[^@"]{1,2000}@[^"]{1,2000})""""
  ]


}
```