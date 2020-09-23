#### Parser Content
```Java
{
Name = s-common-ftp-login-1
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]pass ******""", """ - 200 - - - """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]pass\s+(\S+\s+){2}({outcome}\d+)""",
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = s-common-ftp-failed-login
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]pass ******""", """ - 401 - - - """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]pass\s+(\S+\s+){2}({outcome}\d+)""",
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = s-common-ftp-failed-login-1
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]pass ******""", """ - 530 - - - """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]pass\s+(\S+\s+){2}({outcome}\d+)""",
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = s-common-ftp-upload
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]created /""", """ - 200 """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]created\s+(-|({file_name}\S+))\s""",
    """\]created\s+(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]created\s+\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]created\s+(\S+\s+){2}({outcome}\d+)""",
    """\]created\s+(\S+\s+){4}({bytes}\d+)""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}

{
  Name = s-common-ftp-upload-1
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]created /""", """ - 226 """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,   
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]created\s+(-|({file_name}\S+))\s""",
    """\]created\s+(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]created\s+\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]created\s+(\S+\s+){2}({outcome}\d+)""",
    """\]created\s+(\S+\s+){4}({bytes}\d+)""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}

{
  Name = s-common-ftp-download
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]sent /""", """ - 200 """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]sent\s+(-|({file_name}\S+))\s""",
    """\]sent\s+(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]sent\s+\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]sent\s+(\S+\s+){2}({outcome}\d+)""",
    """\]sent\s+(\S+\s+){3}({bytes}\d+)""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}

{
  Name = s-common-ftp-download-1
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]sent /""", """ - 226 """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]sent\s+(-|({file_name}\S+))\s""",
    """\]sent\s+(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]sent\s+\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]sent\s+(\S+\s+){2}({outcome}\d+)""",
    """\]sent\s+(\S+\s+){3}({bytes}\d+)""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}

{
  Name = s-common-ftp-delete
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]dele """, """ - 250 - - - """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]dele\s+(-|({file_name}\S+))\s""",
    """\]dele\s+(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]dele\s+\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]dele\s+(\S+\s+){2}({outcome}\d+)""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}

{
  Name = s-common-ftp-delete-1
  Vendor = FTP
  Product = FTP
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]dele """, """ - 200 - - - """ ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
    """({host}[\w\.-]+)\s+(\S+\s+){2}\[\d+\]""",
    """({src_ip}\S+)\s+(\S+\s+){2}\[\d+\]""",
    """(-|(({domain}\S+)[\/\\])?({user}\S+))\s+\[\d+\]""",
    """\]dele\s+(-|({file_name}\S+))\s""",
    """\]dele\s+(-|({file_path}({file_parent}\/(\S+\/)?)({file_name}\S+)))\s""",
    """\]dele\s+\/\S+\.({file_ext}[^\/\.\s]+)\s""",
    """\]dele\s+(\S+\s+){2}({outcome}\d+)""",
  ]
  DupFields = [ "host->dest_host", "file_ext->host_file_ext" ]
}
```