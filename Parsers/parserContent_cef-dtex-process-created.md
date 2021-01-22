#### Parser Content
```Java
{
Name = cef-dtex-process-created
  Vendor = Dtex
  Product = Dtex
  Lms = ArcSight
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|ProcessCreated|""" ]
  Fields = [
    """\Wstart=({time}\d+)""",
    """\|Dtex\|([^\|]*\|){2}(ProcessActivity\|)?({activity_type}[^\|]+)\|""",
    """\|Dtex\|([^\|]*\|){3}Running\s*({process}({directory}(?:[^\s\|]+)?[\\\/]+)?({process_name}[^\\\/\|]+))\|""",
    """\|Dtex\|([^\|]*\|){3}Running\s*({path}.+?)\|""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """"ProcessId":\s*"({pid}\d+)"""",
    """\WProcess_Name=(?:\s*|({process_name}.+?)\s+)(\w+=|$)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """\WProcess_Parameters="({path}({process}({directory}(?:[^"]+)?[\\\/]+)?({process_name}[^\\\/\)"]+)))""",
    """\Wreason=({command_line}.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```