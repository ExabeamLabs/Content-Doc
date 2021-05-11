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
    """"EventID":({event_code}\d{1,100})""",
    """"ProcessID":({pid}\d{1,100})""",
    """"Domain":"({domain}[^"]+)"""",
    """"AccountName":"({user}[^"]+)"""",
    """"UserID":"({user_sid}[^"]+)"""",
    """"Message":"({event_name}[^\(:]+?)\s{0,100}\(""",
    """"ScriptBlockId":"({scriptblock_id}[^"]+)"""",
    """({process_name}PowerShell)"""
  ]
}
```