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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}[\w\.-]{1,2000})\s{1,100}pfsvc:""",
    """\suser\s{1,100}'({user_dn}[^']{1,2000})' \(distinguishedName format\)""",
    """\suser\s{1,100}'({user}[^']{1,2000})'""",
    """({auth_method}Primary auth)""",
  ]


}
```