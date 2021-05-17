#### Parser Content
```Java
{
Name = s-azura-mfa-auth-successful
  Vendor = Microsoft
  Product = Microsoft Azure MFA
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """pfsvc: Pfauth succeeded """, """Call status:"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}[\w\.-]{1,2000})\s{1,100}pfsvc:""",
    """\suser\s{1,100}'({user_dn}[^']{1,2000})' \(distinguishedName format\)( from ({src_ip}[\d\.:]{1,2000}?))?\.\s""",
    """\suser\s{1,100}'({user}[^']{1,2000})'( from ({src_ip}[\d\.:]{1,2000}?))?\.\s""",
    """\WCall status:\s{0,100}({call_status}\S+)\s{1,100}-\s{0,100}"({failure_reason}[^"]{1,2000})"\.""",
    """({auth_method}Pfauth)""",
  ]
}
```