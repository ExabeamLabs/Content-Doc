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
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4672)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"Security_ID":"({user_sid}[^"]{1,2000})""",
      """"Source_Logon_ID":"({logon_id}[^"]{1,2000})""",
      """"Privileges":"({privileges}[^"]{1,2000})"""
      """({event_code}4672)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```