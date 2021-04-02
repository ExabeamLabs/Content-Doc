#### Parser Content
```Java
{
Name = json-4104
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4104""", """Microsoft-Windows-PowerShell[""", """"Category":"""", """"ScriptBlockId":""""  ]
  Fields = [
    """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """"Hostname":"({host}[^"]+)"""",
    """"EventID":({event_code}\d+)""",
    """"ProcessID":({pid}\d+)""",
    """"Domain":"({domain}[^"]+)"""",
    """"AccountName":"({user}[^"]+)"""",
    """"UserID":"({user_sid}[^"]+)"""",
    """"Message":"({event_name}[^\(:]+?)\s*\(""",
    """"ScriptBlockId":"({scriptblock_id}[^"]+)"""",
    """({process_name}PowerShell)"""
  ]
}
```