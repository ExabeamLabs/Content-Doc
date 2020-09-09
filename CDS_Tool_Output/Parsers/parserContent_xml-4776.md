#### Parser Content
```Java
{
Name = xml-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ElasticSearch
    DataType = "windows-4776"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["<EventID>4776</EventID>", "<Data Name='Status'>"]
    Fields = [
      """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """<Data Name='Workstation'>(\\+)?(({dest_ip}[A-Fa-f:\d.]+)|(?:(?!NULL)({dest_host}[^\s.]+)(\.[^\s]+)?))</Data>""",
      """<Computer>({host}[^<]+)</Computer>""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """<EventID>({event_code}[^<]+)</EventID>""",
      """<Computer>(?!(?:[A-Fa-f:\d.]+))[^<.]+(\.({domain}[^<.]+)[^<]*)?</Computer>"""
      """<Data Name='TargetUserName'>({user}[^@<]+?)(?:@({domain}[^<.]+)[^<]*)?</Data>""",
      """<Data Name='Status'>({result_code}[^<]+)</Data>""",
    ]
  }
```