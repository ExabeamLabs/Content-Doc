#### Parser Content
```Java
{
Name = cef-dtex-process-created
  Vendor = Dtex Systems
  Product = DTEX InTERCEPT
  Lms = ArcSight
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|ProcessCreated|""" ]
  Fields = [
    """\Wstart=({time}\d{1,100})""",
    """\|Dtex\|([^\|]*\|){2}(ProcessActivity\|)?({activity_type}[^\|]+)\|""",
    """\|Dtex\|([^\|]*\|){3}Running\s{0,100}({process}({directory}(?:[^\s\|]+)?[\\\/]+)?({process_name}[^\\\/\|]+))\|""",
    """\|Dtex\|([^\|]*\|){3}Running\s{0,100}({path}.+?)\|""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """"ProcessId":\s{0,100}"({pid}\d{1,100})"""",
    """\WProcess_Name=(?:\s{0,100}|({process_name}.+?)\s{1,100})(\w+=|$)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """\WProcess_Parameters="({path}({process}({directory}(?:[^"]+)?[\\\/]+)?({process_name}[^\\\/\)"]+)))""",
    """\Wreason=({command_line}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```