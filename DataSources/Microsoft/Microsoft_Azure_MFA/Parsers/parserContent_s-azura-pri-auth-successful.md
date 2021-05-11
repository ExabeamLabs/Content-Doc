#### Parser Content
```Java
{
Name = s-azura-pri-auth-successful
  Vendor = Microsoft
  Product = Microsoft Azure MFA
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """pfsvc: Primary auth succeeded for """ ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s{1,100}pfsvc:""",
    """\suser\s{1,100}'({user_dn}[^']+)' \(distinguishedName format\)""",
    """\suser\s{1,100}'({user}[^']+)'""",
    """({auth_method}Primary auth)""",
  ]
}
```