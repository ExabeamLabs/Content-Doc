#### Parser Content
```Java
{
Name = powershell-process-created
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ """Engine state is changed from None to Available""", """Engine Lifecycle""" ]
  Fields = [
    """({event_name}A new process has been created)""",
    """EventTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"(?i)HostName":\s{0,100}"({host}[^"]{1,2000})"""",
    """Windows PowerShell\s{1,100}\S+\s{1,100}({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}({event_code}\d{1,100})""",
    """({host}[\w.\-]{1,2000}) Engine Lifecycle""",
    """\sHostApplication=({process}(|({directory}[^\s]{1,2000}?))({process_name}[^\s\\\/]{1,2000}).*?)\s{1,100}EngineVersion="""
  ]
  DupFields = [ "host->dest_host", "process->command_line", "directory->process_directory" ]


}
```