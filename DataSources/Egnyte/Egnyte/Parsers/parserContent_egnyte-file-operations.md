#### Parser Content
```Java
{
Name = egnyte-file-operations
  Vendor = Egnyte
  Product = Egnyte
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"file/folder":"""", """"target_path":"""", """"transaction":"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"username":"({user_fullname}[^"\(\)]{1,2000}?)\s{0,100}\(\s{0,100}({user_email}[^@"\)]{1,2000}@[^\\)"\.]{1,2000}\.[^"\)]{1,2000}?)\s{0,100}\)""",
    """"file/folder":"({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})({file_name}[^"\\\/]{1,2000}?(\.({file_ext}[^"\.\\\/]{1,2000}))?))\s{0,100}"""",
    """"transaction":"({accesses}[^"]{1,2000})""",
    """"target_path":"(N/A|({object}[^"]{1,2000}))""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"access":"({service}[^"]{1,2000})""",
    """"ip_address":"({src_ip}[A-Fa-f:.\d]{1,2000})""",
    """({app}Egnyte)"""
  ]
}
```