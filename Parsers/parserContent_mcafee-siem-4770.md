#### Parser Content
```Java
{
Name = mcafee-siem-4770
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4770"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A Kerberos service ticket was renewed""" ]
    Fields = [
      """({event_name}A Kerberos service ticket was renewed)""",
      """"dst_ip":"({src_ip}[^"]+)""",
      """"id":\d*({event_code}4770)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Service_Name":"({service_name}[^"]+)""",
      """"Service_Name":"({dest_host}[^"]+\$)""",
      """({event_code}4770)"""
    ]
  }
```