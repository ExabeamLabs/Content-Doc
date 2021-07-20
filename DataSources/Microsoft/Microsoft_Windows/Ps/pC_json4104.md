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
    """"Hostname":"({host}[^"]{1,2000})"""",
    """"EventID":({event_code}\d{1,100})""",
    """"ProcessID":({pid}\d{1,100})""",
    """"Domain":"({domain}[^"]{1,2000})"""",
    """"AccountName":"({user}[^"]{1,2000})"""",
    """"UserID":"({user_sid}[^"]{1,2000})"""",
    """"Message":"({event_name}[^\(:]{1,2000}?)\s{0,100}\(""",
    """"ScriptBlockId":"({scriptblock_id}[^"]{1,2000})"""",
    """({process_name}PowerShell)"""
  ]
}
```