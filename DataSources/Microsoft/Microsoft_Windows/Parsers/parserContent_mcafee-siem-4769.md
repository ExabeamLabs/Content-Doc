#### Parser Content
```Java
{
Name = mcafee-siem-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A Kerberos service ticket was requested""" ]
    Fields = [
      """({event_name}A Kerberos service ticket was requested)""",
      """"src_ip":"({src_ip}[^"]+)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d{0,100}({event_code}4769)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Service_Name":"({service_name}[^"]+)""",
      """"Service_Name":"({dest_host}[^"]+\$)""",
      """"CommandID":"({result_code}[^"]+)""",
    ]
  }
```