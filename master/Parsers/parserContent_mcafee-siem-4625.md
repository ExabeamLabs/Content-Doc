#### Parser Content
```Java
{
Name = mcafee-siem-4625
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """An account failed to log on""" ]
    Fields = [
      """({event_name}An account failed to log on)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4625)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Security_ID":"({user_sid}[^"]+)""",
      """"Logon_Type":"({logon_type}[^"]+)""",
      """"ObjectID":"({auth_package}[^"]+)""",
      """"Status":"({failure_reason}[^"]+)""",
      """"Sub_Status":"({result_code}[^"]+)""",
    ]
    DupFields = [ "host->dest_host" ]
  }
```