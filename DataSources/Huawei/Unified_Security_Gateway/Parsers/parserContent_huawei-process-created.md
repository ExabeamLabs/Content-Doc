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
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d),\S+\s{1,100}({host}[\w\.\-]{1,2000})""",
     """\sip=({src_ip}[a-fA-F\d.:]{1,2000})""",
     """\suser=(({user_email}[^@,]{1,2000}@[^@,]{1,2000})|({user}[^,]{1,2000}))""",
     """\scommand=({command_line}({process}({directory}[^,]{0,2000}?[\\\/]{1,2000})?({process_name}[^\\\/\s]{1,2000}))[^,]{0,2000}?),""",
     """\sresult=({outcome}\w+)""",
  ]
}
```