#### Parser Content
```Java
{
Name = s-common-ftp-app-activity-8
  Product = FTP
  Conditions = [ """]retr """ ]
}
${UnixParserTemplates.cds-user-activity}{
  Name = cds-account-auth
  Product = CDS
  Conditions = [ """AUDIT:""", """ uid=""", """type=USER_AUTH""" ]
  DataType = "remote-logon"
}
${UnixParserTemplates.cds-user-activity}{
  Name = cds-user-login
  Product = CDS
  Conditions = [ """AUDIT:""", """ uid=""", """type=USER_LOGIN""" ]
  DataType = "remote-logon"
}

{
  Name = raw-unix-process-created
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """; USER=""", """; COMMAND=""" ]
  Fields = [
    """({time}\w+ \d+ \d\d:\d\d:\d\d)\s*:\s*({user}[^:]+?)\s*:""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """; USER=({account}[^;]+?)\s*;""",
    """; COMMAND=({command_line}[^;]+?)\s*(;|$|")""",
    """; COMMAND=({process}({process_directory}[^\s]+[\\\/]+)?({process_name}[^";\\\/\s]+))[\s"](?:|;|$)"""
  ]
  DupFields = [ "process_directory->directory","host->dest_host" ]
}
```