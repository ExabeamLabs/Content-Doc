#### Parser Content
```Java
{
Name = netscaler-process-created
    Vendor = Citrix
    Product = Citrix Netscaler
    Lms = Direct
    DataType = "process-created"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """default """, """ CMD_EXECUTED""", """ Command """ ]
    Fields = [
      """({time}\d+\/\d+\/\d+:\d+:\d+:\d+)(\s*GMT)?\s+({host}[^\s]+)\s+\S+\s*:\s*default\s+\w+\s+CMD_EXECUTED""",
      """\sUser\s+(?:<unknown>|({user}\S+))(\s+\S+){2}\s+({dest_ip}[a-fA-F\d.:]+)""",
      """\sCommand\s+"({command_line}[^"]+?)\s*"""",
      """\sStatus\s+"({outcome}[^"]+)""",
      """\sCommand\s+"({process}({directory}[^\s"]*?[\\\/]+)?({process_name}[^\s\\\/"]+))(\s|")""",
    ]
    DupFields = [ "directory->process_directory" ]
  }
```