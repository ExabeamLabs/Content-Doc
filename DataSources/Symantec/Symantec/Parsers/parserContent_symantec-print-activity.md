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
    """({host}[\w\-.]+)\s+DLP_PROD""",
    """\WURL\s+({additional_info}.+?)\s+FILE_NAME""",
    """\WFILE_NAME\s+({object}.+?)\s+MACHINE_NAME""",
    """\WMACHINE_NAME\s+({src_host}[\w\-.]+)""",
    """\WUSER_NAME\s+(({domain}[^\\\s]+)\\+)?({user_fullname}.+?)\s+APP_NAME""",
    """\WAPP_NAME\s+({app}.+?)\s+MACHINE_IP""",
    """\WMACHINE_IP\s+({src_ip}[A-Fa-f:\d.]+)""",
  ]
}
```