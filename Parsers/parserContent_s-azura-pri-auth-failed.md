#### Parser Content
```Java
{
Name = s-azura-pri-auth-failed
  Vendor = Azura
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """pfsvc: Failed """, """ auth for """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s+pfsvc:""",
    """Failed\s+({auth_method}.+?)\s+auth for """,
    """\suser\s+'({user_dn}[^']+)' \(distinguishedName format\)""",
    """\suser\s+'({user}[^']+)'""",
    """Logon failure:\s*({failure_reason}.+?)(\s*\(|$)""",
  ]
}
```