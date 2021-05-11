#### Parser Content
```Java
{
Name = huawei-process-created
  Vendor = Huawei
  Product = Unified Security Gateway
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """SHELL/""", """ command=""", """ result=""" ]
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d),\S+\s{1,100}({host}[\w\.\-]+)""",
     """\sip=({src_ip}[a-fA-F\d.:]+)""",
     """\suser=(({user_email}[^@,]+@[^@,]+)|({user}[^,]+))""",
     """\scommand=({command_line}({process}({directory}[^,]*?[\\\/]+)?({process_name}[^\\\/\s]+))[^,]*?),""",
     """\sresult=({outcome}\w+)""",
  ]
}
```