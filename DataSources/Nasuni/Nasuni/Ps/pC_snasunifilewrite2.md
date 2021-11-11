#### Parser Content
```Java
{
Name = s-nasuni-file-write-2
  Product = Nasuni
    Conditions = [ """,CIFS,""", """,Truncate File,""" ]
  }
s-nasuni-file-operations = {
  Vendor = Nasuni
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_raw=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """({accesses}[^,]{1,2000}),([^,]{0,2000},){2}(({domain}[^,\\]{1,2000})[\\]{1,2000})?({user}[^,\\]{1,2000}),([^,]{0,2000},){2}("[^"]{1,2000}"|[^,]{0,2000}),[^,]{0,2000},({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({src_file_dir}[^,]{1,2000}\/+)?({src_file_name}[^,\/]{1,2000}),[^,]{1,2000},([^,"]{0,2000},){3}("[^"]{1,2000}"|[^,]{0,2000}),CIFS,""",
    """({file_path}[^,]{1,2000}),([^,"]{0,2000},){4}("[^"]{1,2000}"|[^,]{0,2000}),CIFS,""",
    """(({file_parent}[^,]{1,2000})[\/]{1,2000})?({file_name}[^\/,]{1,2000}?(\.({file_ext}[^\/,\.]{1,2000}))?),([^,"]{0,2000},){4}("[^"]{1,2000}"|[^,]{0,2000}),CIFS,""",
    """({file_path}[^,]{1,2000}),([^,"]{0,2000},){3}("[^"]{1,2000}"|[^,]{0,2000}),CIFS,""",
    """(({file_parent}[^,]{1,2000})[\/]{1,2000})?({file_name}[^\/,]{1,2000}?(\.({file_ext}[^\/,\.]{1,2000}))?),([^,"]{0,2000},){3}("[^"]{1,2000}"|[^,]{0,2000}),CIFS,""",
  ]
  DupFields = [ "host->dest_host" ]}
```