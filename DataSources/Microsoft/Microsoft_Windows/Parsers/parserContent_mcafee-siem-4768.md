#### Parser Content
```Java
{
Name = mcafee-siem-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """A Kerberos authentication ticket (TGT) was requested""" ]
    Fields = [
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})""",
      """"id":\d{0,100}({event_code}4768)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]{1,2000})""",
      """"HostID":"({host}[^"]{1,2000})""",
      """"UserIDSrc":"({user}[^"]{1,2000})""",
      """"CommandID":"({result_code}[^"]{1,2000})""",
      """"src_ip":"({src_ip}[^"]{1,2000})""",
      """"Service_Name":"({service_name}[^"]{1,2000})""",
    ]
    DupFields = ["host->dest_host"]
  }
```