#### Parser Content
```Java
{
Name = mcafee-siem-4768
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A Kerberos authentication ticket (TGT) was requested""" ]
    Fields = [
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4768)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"CommandID":"({result_code}[^"]+)""",
    ]
    DupFields = ["host->dest_host"]
  }
```