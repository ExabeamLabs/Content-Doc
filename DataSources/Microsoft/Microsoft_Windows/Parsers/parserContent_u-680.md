#### Parser Content
```Java
{
Name = u-680
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Sumo
  DataType = "windows-680"
  TimeFormat = "yyyyMMddHHmmss.SSS"
  Conditions = [ "EventCode = 680;", """Logon attempt by:""" ]
  Fields = [ """Computer(Name)? = "+({host}[^"]+)"""",
    """({event_name}Logon attempt)""",
             """EventCode = ({event_code}\d+)""",
             """TimeGenerated = "({time}[\d]+.\d\d\d)""",
             """Logon account:\s+({user}[^@]+?)(?:@({domain}[^\s.]+)[^\s]*)?\s+Source Workstation:\s+({dest_host}[^\s]+)""",
             """Error Code:\s+({result_code}[\w\-]+)"""
	]
}
```