#### Parser Content
```Java
{
Name = windows-xml-powershell-process-created
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
  Conditions = [ """>Windows PowerShell<""", """<Message>Engine state is changed from None to Available""", """Engine Lifecycle""", """>400</EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z'\/>""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """\sHostApplication=({process}({process_name}[^\s\\\/]{1,2000})[^=]{0,2000}?)\s{1,100}EngineVersion=""",
    """({event_name}Engine state is changed from None to Available)""",
    """({event_code}\d{1,20})<\/EventID>""",
    """<Keywords>({outcome}[^<]{1,2000})""",
    """<EventRecordID>({record_id}[^<]{1,2000})"""
  ]
  DupFields = [ "host->dest_host", "process->command_line" ]


}
```