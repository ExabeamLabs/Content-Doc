#### Parser Content
```Java
{
Name = s-windows-process-created
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-process-created"
  IsHVF = true
  TimeFormat = "yyyyMMddHHmmss.SSSSSS"
  Conditions = [ """ProcessName="""", """ProcessId=""", """CommandLine="""" ]
  Fields = [
    """StartTime="({time}\d+\.\d+)""",
    """Host="({host}[^"]+)""",
    """ProcessId=({process_guid}.+?)\s+(\w+=|$)""",
    """CommandLine="*({command_line}[^"]+?)\s*"""",
    """Path="({path}[^"]+)""",
    """Path="({process}({directory}[^"]+?)({process_name}[^"\\]+))"""",
    """ProcessName="({process_name}[^"]+)""",
  ]
  DupFields = [ "host->dest_host", "process_guid->pid", "directory->process_directory" ]
}
```