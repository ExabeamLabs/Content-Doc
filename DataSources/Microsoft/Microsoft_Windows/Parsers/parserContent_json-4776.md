#### Parser Content
```Java
{
Name = json-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""4776""", """"PackageName":"""", """attempted to validate the credentials for an account"""]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """"EventTime":({time}\d+)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"(Hostname|MachineName)":"({host}[^"]*)""",
      """"Computer"+:"+({host}[^"]+)"""",
      """({event_code}4776)""",
      """"TargetUserName":"({user}[^"]*)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """"(Hostname|MachineName)":"(?!(?:[A-Fa-f:\d.]+))[^."]*\.({domain}[^.]*)""",
      """"TargetUserName":"[^"@]+(?:@({domain}[^"@\s]+)[^"]*)?""",
      """"Status":"({result_code}[^"]*)""",
      """"Workstation":"\\*({dest_host}[^"]+)""",
    ]
  }
```