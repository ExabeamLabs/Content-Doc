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
    """StartTime="({time}\d{1,100}\.\d{1,100})""",
    """Host="({host}[^"]+)""",
    """ProcessId=({process_guid}.+?)\s{1,100}(\w+=|$)""",
    """CommandLine="{0,20}({command_line}[^"]+?)\s{0,100}"""",
    """Path="({path}[^"]+)""",
    """Path="({process}({directory}[^"]+?)({process_name}[^"\\]+))"""",
    """ProcessName="({process_name}[^"]+)""",
  ]
  DupFields = [ "host->dest_host", "process_guid->pid", "directory->process_directory" ]
}
```