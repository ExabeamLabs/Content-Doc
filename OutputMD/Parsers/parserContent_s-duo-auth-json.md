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
    """"device":\s*"*(null\}?|({host}[\w\-.]+))"""",
    """"ip"\s*:\s*"({src_ip}[^"]+)"""",
    """"username"\s*:\s*"(?:({domain}[^\\"]+)\\)?({user}[^"]+)"""",
    """"factor"\s*:\s*"(?:n\/a|({auth_method}[^"]+))"""",
    """"os"\s*:\s*"({os}[^"]+)"""",
    """"os_version"\s*:\s*"({os_version}[^"]+)"""",
    """"browser"\s*:\s*"({browser}[^"]+)"""",
    """"browser_version"\s*:\s*"({browser_version}[^"]+)"""",
    """"result"\s*:\s*"({outcome}[^"]+)"""",
    """"reason"\s*:\s*"({failure_reason}[^"]+)"""",
    """"new_enrollment"\s*:\s*({new_enrollment}true|false)""",
    """"*integration"*:\s*"*({service}[^"]+)"""
  ]
}
```