#### Parser Content
```Java
{
Name = observeit-audit-logins
  Vendor = ObserveIT
  Product = ObserveIT
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """EventName=Audit_logins;""", """; AuditTime=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\S+)\s{1,100}(\S+\s{1,100}){4}EventName=""",
    """\sAuditTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sDomainName=({domain}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sConsoleUser=({user}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sLoginStatus=({outcome}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sLoginStatusDescrition=({failure_reason}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
  ]
}
```