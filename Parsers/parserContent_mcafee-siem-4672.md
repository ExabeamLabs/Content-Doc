#### Parser Content
```Java
{
Name = mcafee-siem-4672
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """Special privileges assigned to new logon.""" ]
    Fields = [
      """({event_name}Special privileges assigned to new logon)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4672)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Security_ID":"({user_sid}[^"]+)""",
      """"Source_Logon_ID":"({logon_id}[^"]+)""",
      """"Privileges":"({privileges}[^"]+)"""
      """({event_code}4672)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```