#### Parser Content
```Java
{
Name = raw-defender-av-1116
 Vendor = Microsoft
 Product = Defender Antivirus
 Lms = Direct
 DataType = "security-alert"
 TimeFormat = "yyyy-MM-dd HH:mm:ss"
 Conditions = [ """EventCode=1116""", """LogName =Microsoft-Windows-Windows Defender/Operational""", """Detection Origin:""", """Detection Type:""", """Detection Source:""", """Signature Version:""" ]
 Fields = [
   """ComputerName =({host}[^\s]{1,2000})""",
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """EventCode=({event_code}\d{1,100})""",
   """User:\s{0,100}(NT AUTHORITY|({domain}[^\\]{1,2000}))(\\)?(SYSTEM|({user}[^\s]{1,2000}))""",
   """Sid=({user_sid}[^\s]{1,2000})""",
   """Message=({additional_info}[^\.]{1,2000})\.""",
   """Name:\s{0,100}({alert_name}[^\s]{1,2000})""",
   """Detection Type:\s{0,100}({alert_type}[^\s]{1,2000})""",
   """Severity:\s{0,100}({alert_severity}[^\s]{1,2000})"""
 ]


}
```