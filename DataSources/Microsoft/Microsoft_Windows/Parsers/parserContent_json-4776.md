#### Parser Content
```Java
{
Name = json-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "MM/dd/yyyy H:mm:ss a"
    Conditions = ["""4776""", """"PackageName":""""]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s*({time}\d+)""",
      """"timestamp":\s*({time}\d+)""",
      """"(Hostname|MachineName)":"({host}[^"]*)""",
      """({event_code}4776)""",
      """"TargetUserName":"({user}[^"]*)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """"(Hostname|MachineName)":"(?!(?:[A-Fa-f:\d.]+))[^."]*\.({domain}[^.]*)""",
      """"TargetUserName":"[^"@]+(?:@({domain}[^"@\s]+)[^"]*)?""",
      """"Status":"({result_code}[^"]*)""",
      """"Workstation":"({dest_host}[^"]*)""",
    ]
  }
```