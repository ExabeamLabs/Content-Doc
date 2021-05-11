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
  Fields = [ """Computer(Name)? = "{1,20}({host}[^"]+)"""",
    """({event_name}Logon attempt)""",
             """EventCode = ({event_code}\d{1,100})""",
             """TimeGenerated = "({time}[\d]+.\d\d\d)""",
             """Logon account:\s{1,100}({user}[^@]+?)(?:@({domain}[^\s.]+)[^\s]*)?\s{1,100}Source Workstation:\s{1,100}({dest_host}[^\s]+)""",
             """Error Code:\s{1,100}({result_code}[\w\-]+)"""
	]
}
```