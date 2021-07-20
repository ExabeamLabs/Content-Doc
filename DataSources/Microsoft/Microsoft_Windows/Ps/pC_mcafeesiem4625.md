#### Parser Content
```Java
{
Name = mcafee-siem-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """An account failed to log on""" ]
    Fields = [
      """({event_name}An account failed to log on)""",
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4625)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"Security_ID":"({user_sid}[^"]{1,2000})""",
      """"Logon_Type":"({logon_type}[^"]{1,2000})""",
      """"ObjectID":"({auth_package}[^"]{1,2000})""",
      """"Status":"({failure_reason}[^"]{1,2000})""",
      """"Sub_Status":"({result_code}[^"]{1,2000})""",
    ]
    DupFields = [ "host->dest_host" ]
  }
```