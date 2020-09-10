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
             """EvntSLog:\s+\[.+\]\s+({time}\w+ \w+ \d+ \d+:\d+:\d+ \d+):\s+({host}[\w. /\\]+)\/.*\s+\(({event_code}\w+)\)""",
             """User Name:\s+({user}.+?)\s+Supplied Realm Name:\s+({domain}[^\s]+)""",
             """Client Address:\s+({dest_ip}[a-fA-F:\d.]+)""",
             """Result Code:\s+({result_code}[\w\-]+)""",
             """User ID:\s\%\{({user_sid}[^}]+)\}"""
  ]
}
```