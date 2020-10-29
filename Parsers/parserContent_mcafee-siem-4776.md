#### Parser Content
```Java
{
Name = mcafee-siem-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """McAfee_SIEM:""", """The domain controller attempted to validate the credentials for an account""" ]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """"dst_ip":"({dest_ip}[^"]+)""",
      """"id":\d*({event_code}4776)""",
      """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"DomainID":"({domain}[^"]+)""",
      """"HostID":"({host}[^"]+)""",
      """"UserIDSrc":"({user}[^"]+)""",
      """"Status":"({result_code}[^"]+)""",
      """"src_ip":"({src_ip}[^"]+)""",
    ]
    DupFields = [ "host->dest_host" ]
  }
```