#### Parser Content
```Java
{
Name = xml-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ElasticSearch 
    DataType = "windows-4768"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["<EventID>4768</EventID>", "<Data Name='TargetSid'>"]
    Fields = [
      """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """<Computer>({host}[^<]+)</Computer>""",
      """<EventID>({event_code}[^<]+)</EventID>""",
      """<Data Name='TargetSid'>({user_sid}[^<]+)</Data>""",
      """<Data Name='Status'>({result_code}[^<]+)</Data>""",
      """<Data Name='TargetUserName'>(?=\w)({user}[^<]+)</Data>""",
      """<Data Name='TargetDomainName'>(?=\w)({domain}[^<]+)</Data>""",
      """<Data Name='IpAddress'>(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)"""
    ]
  }
```