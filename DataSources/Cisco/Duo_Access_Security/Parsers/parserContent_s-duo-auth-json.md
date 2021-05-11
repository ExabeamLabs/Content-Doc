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
    """exabeam_host=({host}[^\s]+)""",
    """"device":\s{0,100}"{0,20}(null\}?|({host}[\w\-.]+))"""",
    """"ip"\s{0,100}:\s{0,100}"({src_ip}[^"]+)"""",
    """"username"\s{0,100}:\s{0,100}"(?:({domain}[^\\"]+)\\)?({user}[^"]+)"""",
    """"factor"\s{0,100}:\s{0,100}"(?:n\/a|({auth_method}[^"]+))"""",
    """"os"\s{0,100}:\s{0,100}"({os}[^"]+)"""",
    """"os_version"\s{0,100}:\s{0,100}"({os_version}[^"]+)"""",
    """"browser"\s{0,100}:\s{0,100}"({browser}[^"]+)"""",
    """"browser_version"\s{0,100}:\s{0,100}"({browser_version}[^"]+)"""",
    """"result"\s{0,100}:\s{0,100}"({outcome}[^"]+)"""",
    """"reason"\s{0,100}:\s{0,100}"({failure_reason}[^"]+)"""",
    """"new_enrollment"\s{0,100}:\s{0,100}({new_enrollment}true|false)""",
    """"{0,20}integration"{0,20}:\s{0,100}"{0,20}({service}[^"]+)"""
  ]
}
```