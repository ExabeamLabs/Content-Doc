#### Parser Content
```Java
{
Name = windows-xml-powershell-process-created-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
  Conditions = [ """>Windows PowerShell<""", """is Started""", """<Task>Provider Lifecycle</Task>""", """>600</EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z'\/>""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """\sHostApplication=({process}(|({directory}[^\s]{1,2000}?))({process_name}[^\s\\\/]{1,2000})[^=]{0,2000}?)\s{1,100}EngineVersion=""",
    """<Message>({event_name}[^:=<.]{1,2000})\.""",
    """({event_code}\d{1,20})<\/EventID>""",
    """<Keywords>({outcome}[^<]{1,2000})""",
    """<EventRecordID>({record_id}[^<]{1,2000})"""
  ]
  DupFields = [ "host->dest_host", "process->command_line", "directory->process_directory" ]


}
```