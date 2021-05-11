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
    """Windows PowerShell\s{1,100}\S+\s{1,100}({time}\w+ \w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}({event_code}\d{1,100})""",
    """({host}[\w.\-]+) Provider Lifecycle""",
    """\sHostApplication=({process}(|({directory}[^\s]+?))({process_name}[^\s\\\/]+)).*?\s{1,100}EngineVersion=""",
    """\sHostApplication=({command_line}.+?)\s{1,100}EngineVersion="""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```