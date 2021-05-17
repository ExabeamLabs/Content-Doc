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
    """\|Dtex\|([^\|]{0,2000}\|){2}(ProcessActivity\|)?({activity_type}[^\|]{1,2000})\|""",
    """\|Dtex\|([^\|]{0,2000}\|){3}Running\s{0,100}({process}({directory}(?:[^\s\|]{1,2000})?[\\\/]{1,2000})?({process_name}[^\\\/\|]{1,2000}))\|""",
    """\|Dtex\|([^\|]{0,2000}\|){3}Running\s{0,100}({path}.+?)\|""",
    """\WDevice_Name=(({domain}[^\\]{1,2000})\\+)?({host}[^\\\s]{1,2000})""",
    """"ProcessId":\s{0,100}"({pid}\d{1,100})"""",
    """\WProcess_Name=(?:\s{0,100}|({process_name}.+?)\s{1,100})(\w+=|$)""",
    """\WUser_Name=(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})\s""",
    """\WProcess_Parameters="({path}({process}({directory}(?:[^"]{1,2000})?[\\\/]{1,2000})?({process_name}[^\\\/\)"]{1,2000})))""",
    """\Wreason=({command_line}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```