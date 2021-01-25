#### Parser Content
```Java
{
Name = s-azura-pri-auth-successful
  Vendor = Azura
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """pfsvc: Primary auth succeeded for """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s+pfsvc:""",
    """\suser\s+'({user_dn}[^']+)' \(distinguishedName format\)""",
    """\suser\s+'({user}[^']+)'""",
    """({auth_method}Primary auth)""",
  ]
}
```