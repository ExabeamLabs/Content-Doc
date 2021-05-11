#### Parser Content
```Java
{
Name = evntslog-672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-672"
  TimeFormat = "E MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Name:", "krbtgt", "(672)" ]
  Fields = [ """exabeam_host=({host}[\w.\-]+)""",
             """EvntSLog:\s{1,100}\[.+\]\s{1,100}({time}\w+ \w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}):\s{1,100}({host}[\w. /\\]+)\/.*\s{1,100}\(({event_code}\w+)\)""",
             """User Name:\s{1,100}({user}.+?)\s{1,100}Supplied Realm Name:\s{1,100}({domain}[^\s]+)""",
             """Client Address:\s{1,100}({dest_ip}[a-fA-F:\d.]+)""",
             """Result Code:\s{1,100}({result_code}[\w\-]+)""",
             """User ID:\s\%\{({user_sid}[^}]+)\}"""
  ]
  DupFields = ["host->dest_host"]
}
```