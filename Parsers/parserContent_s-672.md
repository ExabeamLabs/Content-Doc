#### Parser Content
```Java
{
Name = s-672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-672"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ "EventCode=672", "Service Name:", "krbtgt" ]
  Fields = [ """exabeam_raw=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
    """({event_name}Account Logon)""",
             """ComputerName=({host}[\w.\-]+)""",
             """EventCode=({event_code}\w+)""",
             """User Name:\s+({user}.+?)\s+Supplied Realm Name:\s+({domain}[^\s]+)""",
             """Client Address:\s+(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
             """Result Code:\s+({result_code}[\w\-]+)""",
             """Sid=({user_sid}[^\s]+)\s+SidType"""
  ]
}
```