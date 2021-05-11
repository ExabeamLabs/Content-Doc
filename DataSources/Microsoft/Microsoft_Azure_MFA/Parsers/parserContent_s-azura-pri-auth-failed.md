#### Parser Content
```Java
{
Name = s-azura-pri-auth-failed
  Vendor = Microsoft
  Product = Microsoft Azure MFA
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """pfsvc: Failed """, """ auth for """ ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s{1,100}pfsvc:""",
    """Failed\s{1,100}({auth_method}.+?)\s{1,100}auth for """,
    """\suser\s{1,100}'({user_dn}[^']+)' \(distinguishedName format\)""",
    """\suser\s{1,100}'({user}[^']+)'""",
    """Logon failure:\s{0,100}({failure_reason}.+?)(\s{0,100}\(|$)""",
  ]
}
```