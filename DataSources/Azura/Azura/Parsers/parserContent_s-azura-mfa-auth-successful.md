#### Parser Content
```Java
{
Name = s-azura-mfa-auth-successful
  Vendor = Azura
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """pfsvc: Pfauth succeeded """, """Call status:"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s+pfsvc:""",
    """\suser\s+'({user_dn}[^']+)' \(distinguishedName format\)( from ({src_ip}[\d\.:]+?))?\.\s""",
    """\suser\s+'({user}[^']+)'( from ({src_ip}[\d\.:]+?))?\.\s""",
    """\WCall status:\s*({call_status}\S+)\s+-\s*"({failure_reason}[^"]+)"\.""",
    """({auth_method}Pfauth)""",
  ]
}
```