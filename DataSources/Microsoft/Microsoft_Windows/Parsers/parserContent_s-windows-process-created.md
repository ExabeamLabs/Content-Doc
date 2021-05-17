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
    """Host="({host}[^"]{1,2000})""",
    """ProcessId=({process_guid}.+?)\s{1,100}(\w+=|$)""",
    """CommandLine="{0,20}({command_line}[^"]{1,2000}?)\s{0,100}"""",
    """Path="({path}[^"]{1,2000})""",
    """Path="({process}({directory}[^"]{1,2000}?)({process_name}[^"\\]{1,2000}))"""",
    """ProcessName="({process_name}[^"]{1,2000})""",
  ]
  DupFields = [ "host->dest_host", "process_guid->pid", "directory->process_directory" ]
}
```