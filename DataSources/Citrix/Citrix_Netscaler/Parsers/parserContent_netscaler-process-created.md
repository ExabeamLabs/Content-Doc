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
      """({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100})(\s{0,100}GMT)?\s{1,100}({host}[^\s]+)\s{1,100}\S+\s{0,100}:\s{0,100}default\s{1,100}\w+\s{1,100}CMD_EXECUTED""",
      """\sUser\s{1,100}(?:<unknown>|({user}\S+))(\s{1,100}\S+){2}\s{1,100}({dest_ip}[a-fA-F\d.:]+)""",
      """\sCommand\s{1,100}"({command_line}[^"]+?)\s{0,100}"""",
      """\sStatus\s{1,100}"({outcome}[^"]+)""",
      """\sCommand\s{1,100}"({process}({directory}[^\s"]*?[\\\/]+)?({process_name}[^\s\\\/"]+))(\s|")""",
    ]
    DupFields = [ "directory->process_directory" ]
  }
```