#### Parser Content
```Java
{
Name = seclore-file-permission-change-2
  DataType = "file-permission-change"
  Conditions = [ """"machine_name"""", """"activity":""", """"user_name":""", """"offline_access_right":""", """"activity":7""" ]
  Fields = ${SecloreParserTemplates.seclore-file-operations.Fields}[
    """"activity":({accesses}7)"""
  ]

seclore-file-operations = {
  Vendor = Seclore
  Product = Seclore
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"creation_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"machine_name":"({host}[^"]{1,2000})?"""",
    """"machine_ip1":"({dest_ip}[A-Fa-f\d\.:]{1,2000})?""",
    """"user_name":"({user_fullname}[^"]{1,2000})"""",
    """"user_email_id":"({user_email}[^\@]{1,2000}\@[^"]{1,2000})"""",
    """"current_file_name":"({file_name}[^"]{1,2000})"""",
    """"current_location":"({file_path}[^"]{1,2000})?"""",
    """"source_location":"({src_file_dir}[^"]{1,2000})?"""",
    """"file_name":"({src_file_name}[^"]{1,2000})"""",
    """"activity_comments":"{0,20}(null|({additional_info}[^",]{1,2000}))""",
    """"authorized":({outcome}\d{1,100})"""
  
}
```