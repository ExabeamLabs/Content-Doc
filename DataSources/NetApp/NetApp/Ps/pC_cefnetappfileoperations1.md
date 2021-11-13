#### Parser Content
```Java
{
Name = cef-netapp-file-operations-1
  Vendor = NetApp
  Product = NetApp
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"timestamp"""", """"volumeName""", """"netapp""", """"entityAccessedTime""", """"activityType""" ]
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,9}Z)""",
    """"hostname":"({host}[^"]{1,2000})"""",
    """"userDisplayName\\{0,20}":\\{0,20}"({user_fullname}[^"]{1,2000}?)\\{0,20}"""",
    """"entityType\\{0,20}":\\{0,20}"({file_type}[^"]{1,2000}?)\\{0,20}"""",
    """"userName\\{0,20}":\\{0,20}"({user}[^"]{1,2000}?)\\{0,20}"""",
    """"domain\\{0,20}":\\{0,20}"({domain}[^"]{1,2000}?)\\{0,20}"""",
    """"extension\\{0,20}":\\{0,20}"({file_ext}[^"]{1,2000}?)\\{0,20}"""",
    """"entityName\\{0,20}":\\{0,20}"({file_name}[^"]{1,2000}?)\\{0,20}"""",
    """"entityPath\\{0,20}":\\{0,20}"({file_path}({file_parent}[^"]{0,2000}?)[\\\/]{0,20}[^\/"]{1,2000}?)\\{0,20}"""",
    """"activityType\\{0,20}":\\{0,20}"({activity}[^"]{1,2000}?)\\{0,20}"""",
    """"host\\{0,20}":\\{0,20}"({dest_ip}[a-fA-F\d:.]{1,2000})\\{0,20}""""
  ]
  DupFields = [ "activity->accesses" ]


}
```