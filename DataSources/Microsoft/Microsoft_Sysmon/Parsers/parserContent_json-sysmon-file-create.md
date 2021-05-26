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
    """"Image":"({process}({directory}[^"]{0,2000}[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))""",
    """"TargetFilename":"({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
    """"Domain":"((?i)NT AUTHORITY|({domain}[^"]{1,2000}))""",
    """"AccountName":"((?i)SYSTEM|({user}[^"]{1,2000}))""",
    """"ProcessID":({pid}\d{1,100})""",
    """"Hostname":"({host}[^"]{1,2000})""",
    """Category":"({event_name}[^"]{1,2000})""",
    """"CreationUtcTime":"({creation_utc_time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)""",
    """EventID":({event_code}\d{1,100})""",
  ]
}
```