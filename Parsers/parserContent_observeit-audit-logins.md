#### Parser Content
```Java
{
Name = observeit-audit-logins
  Vendor = ObserveIT
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """EventName=Audit_logins;""", """; AuditTime=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}\S+)\s+(\S+\s+){4}EventName=""",
    """\sAuditTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]+?)\s*(;|"*\s*$)""",
    """\sDomainName=({domain}[^;]+?)\s*(;|"*\s*$)""",
    """\sConsoleUser=({user}[^;]+?)\s*(;|"*\s*$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]+)""",
    """\sLoginStatus=({outcome}[^;]+?)\s*(;|"*\s*$)""",
    """\sLoginStatusDescrition=({failure_reason}[^;]+?)\s*(;|"*\s*$)""",
  ]
}
```