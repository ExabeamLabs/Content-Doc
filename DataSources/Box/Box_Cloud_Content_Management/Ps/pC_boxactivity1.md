#### Parser Content
```Java
{
Name = box-activity-1
  Product = Box Cloud Content Management
  Conditions = [ """,PREVIEW,""", """","icam-""" ]
}
box-activity-1 = {
  Vendor = Box
  Product = Box
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d[\+\-]\d{1,100})","{0,20}({user}[^\s",]{1,2000})"{0,20},"{0,20}({accesses}[^",]{1,2000})"{0,20},"{0,20}((?i)UNKNOWN|({file_class}[^",]{1,2000}))"{0,20},"{0,20}({file_name}[^"]{1,2000}?(\.({file_ext}[^\/,"\.\s]{1,2000}))?)"{0,20},"({file_path}({file_parent}[^"]{1,2000}\/)?[^"]{0,2000})"{0,20},[^,]{0,2000},"{0,20}((?i)UNKNOWN|({file_type}[^",]{1,2000}))"{0,20}(,"{0,20}({user_email}[^",\s@]{1,2000}@[^",\s@]{1,2000})"{0,20},"{0,20}((?i)no_value|({src_host}[^",]{1,2000}))"{0,20},([^,]{0,2000},){2}"{0,20}({src_ip}[A-Fa-f:\d.]{1,2000})")?""",
  ]}
```