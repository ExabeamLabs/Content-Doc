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
  Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """({event_name}Account Logon)""",
             """ComputerName=({host}[\w.\-]+)""",
             """EventCode=({event_code}\w+)""",
             """User Name:\s{1,100}({user}.+?)\s{1,100}Supplied Realm Name:\s{1,100}({domain}[^\s]+)""",
             """Client Address:\s{1,100}(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
             """Result Code:\s{1,100}({result_code}[\w\-]+)""",
             """Sid=({user_sid}[^\s]+)\s{1,100}SidType"""
  ]
}
```