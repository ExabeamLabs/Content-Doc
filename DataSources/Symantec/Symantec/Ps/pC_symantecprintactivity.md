#### Parser Content
```Java
{
Name = symantec-print-activity
  Vendor = Symantec
  Product = Symantec
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Endpoint Printer/Fax INCIDENT""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000})\s{1,100}DLP_PROD""",
    """\WURL\s{1,100}({additional_info}.+?)\s{1,100}FILE_NAME""",
    """\WFILE_NAME\s{1,100}({object}.+?)\s{1,100}MACHINE_NAME""",
    """\WMACHINE_NAME\s{1,100}({src_host}[\w\-.]{1,2000})""",
    """\WUSER_NAME\s{1,100}(({domain}[^\\\s]{1,2000})\\+)?({user_fullname}.+?)\s{1,100}APP_NAME""",
    """\WAPP_NAME\s{1,100}({app}.+?)\s{1,100}MACHINE_IP""",
    """\WMACHINE_IP\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
  ]
}
```