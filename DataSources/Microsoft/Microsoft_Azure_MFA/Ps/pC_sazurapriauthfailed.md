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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}[\w\.-]{1,2000})\s{1,100}pfsvc:""",
    """Failed\s{1,100}({auth_method}.+?)\s{1,100}auth for """,
    """\suser\s{1,100}'({user_dn}[^']{1,2000})' \(distinguishedName format\)""",
    """\suser\s{1,100}'({user}[^']{1,2000})'""",
    """Logon failure:\s{0,100}({failure_reason}.+?)(\s{0,100}\(|$)""",
  ]


}
```