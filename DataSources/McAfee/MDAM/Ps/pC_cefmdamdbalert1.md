#### Parser Content
```Java
{
Name = cef-mdam-db-alert-1
  Vendor = McAfee
  Product = MDAM
  Lms = ArcSight
  DataType = "database-alert"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|McAfee|Database Security|""", """|alert|"""]
  Fields = [
    """Exec_Time=\\"({time}\d\d\s\w\w\w\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """({host}[\w\-\.]{1,2000})\s{0,100}CEF:""",
    """\|alert\|({alert_name}[^\|]{1,2000})""",
    """Src_Host=\\"(\.|({src_host}[\w\-\.]{1,2000}))""",
    """Src_IP=\\"({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """Severity=\\"({alert_severity}[^"\\]{1,2000})""",
    """DB_Name =\\"({database_name}[^"]{1,2000})\\"""",
    """\sExec_User=\\"(({domain}[^\\]{1,2000})\\+)?({user}[^"\\]{1,200})""",
    """OS_User=\\"([^\\]{1,2000}\\+)?({os_user}[^"\\]{1,200})""",
    """Statement=\\"({db_query}({db_operation}\w{1,2000})[^,]{1,2000}?)\s{0,100}\\"{1,20

}
```