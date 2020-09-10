#### Parser Content
```Java
{
Name = powershell-process-created-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ """Provider""", """is Started""", """Provider Lifecycle""" ]
  Fields = [
    """({event_name}A new process has been created)""",
    """Windows PowerShell\s+\S+\s+({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+({event_code}\d+)""",
    """({host}[\w.\-]+) Provider Lifecycle""",
    """\sHostApplication=({process}(|({directory}[^\s]+?))({process_name}[^\s\\\/]+)).*?\s+EngineVersion=""",
    """\sHostApplication=({command_line}.+?)\s+EngineVersion="""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```