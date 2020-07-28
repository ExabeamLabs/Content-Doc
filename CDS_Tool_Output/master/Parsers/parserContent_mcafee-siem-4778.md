#### Parser Content
```Java
{
Name = mcafee-siem-4778
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-4778"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A session was reconnected to a Window Station.""" ]
    Fields = [
      """({event_name}A session was reconnected to a Window Station)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4778)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Source_Logon_ID":"({logon_id}[^"]+)""",
    ]
  }
```