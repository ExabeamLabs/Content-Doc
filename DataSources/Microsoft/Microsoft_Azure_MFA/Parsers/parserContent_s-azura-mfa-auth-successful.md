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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s{1,100}pfsvc:""",
    """\suser\s{1,100}'({user_dn}[^']+)' \(distinguishedName format\)( from ({src_ip}[\d\.:]+?))?\.\s""",
    """\suser\s{1,100}'({user}[^']+)'( from ({src_ip}[\d\.:]+?))?\.\s""",
    """\WCall status:\s{0,100}({call_status}\S+)\s{1,100}-\s{0,100}"({failure_reason}[^"]+)"\.""",
    """({auth_method}Pfauth)""",
  ]
}
```