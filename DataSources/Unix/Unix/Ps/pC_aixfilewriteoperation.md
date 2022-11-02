#### Parser Content
```Java
{
Name = aix-file-write-operation
  DataType = "file-write"
  Conditions = [ """assh:""", """FILE_Write""" ]

aix-template= {
  Vendor = Unix
  Product = Unix
  Lms = Direct
  TimeFormat = "MMM yyyy HH:mm:ss.SSSSSS"
  Fields = [
   """({time}\w\w\w\s\d\d\d\d\s\d\d:\d\d:\d\d\.\d\d\d\d\d\d)""",
   """({host}[\w\-\.]{1,2000})\sassh:""",
   """({activity}FILE_\w{1,2000})""",
   """({activity}PROC_\w{1,2000})""",
   """filename\s{1,100}(:|=|)\s{1,100}(|(({file_path}[^@"]{0,2000}\/)?(null|({file_name}[^@"]{0,2000}))))\s{1,100}(FILE_|PROC_)""",
   """(FILE_|PROC_)\w{1,2000}\s{1,2000}(|({command_line}[^\s]{1,2000}?))\s{1,2000}""",
   """\sassh:\s{0,100}[^@"]{0,2000}(FILE_|PROC_)\w{1,2000}\s{0,100}[\w\-\.]{1,2000}\s{0,1000}({user}[\w\-\.]{1,2000})""",
  ]
   DupFields = ["host->dest_host"
}
```