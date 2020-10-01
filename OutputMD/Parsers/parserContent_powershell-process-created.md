#### Parser Content
```Java
{
Name = powershell-process-created
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ """Engine state is changed from None to Available""", """Engine Lifecycle""" ]
  Fields = [
    """({event_name}A new process has been created)""",
    """Windows PowerShell\s+\S+\s+({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+({event_code}\d+)""",
    """({host}[\w.\-]+) Engine Lifecycle""",
    """\sHostApplication=({process}(|({directory}[^\s]+?))({process_name}[^\s\\\/]+).*?)\s+EngineVersion="""
  ]
  DupFields = [ "host->dest_host", "process->command_line", "directory->process_directory" ]
}
```