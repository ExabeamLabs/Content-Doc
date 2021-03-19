#### Parser Content
```Java
{
Name = json-sysmon-file-create
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """Microsoft-Windows-Sysmon""", """File created""", """"AccountName":"""", """"EventID":11""" ]
  Fields = [
    """"UtcTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """"Image":"({process}({directory}[^"]*[\\\/]+)?({process_name}[^"\\\/]+))""",
    """"TargetFilename":"({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
    """"Domain":"((?i)NT AUTHORITY|({domain}[^"]+))""",
    """"AccountName":"((?i)SYSTEM|({user}[^"]+))""",
    """"ProcessID":({pid}\d+)""",
    """"Hostname":"({host}[^"]+)""",
    """Category":"({event_name}[^"]+)""",
    """"CreationUtcTime":"({creation_utc_time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)""",
    """EventID":({event_code}\d+)""",
  ]
}
```