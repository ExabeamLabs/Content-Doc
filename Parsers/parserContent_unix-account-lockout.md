#### Parser Content
```Java
{
Name = unix-account-lockout
  DataType = "account-lockout"
  Conditions = [ """[][][""", """ pam_faillock(sshd:auth): User unknown: """ ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sUser unknown:\s*(({domain}[^\\]+?)\\+)?({user}[^\\]+?)\s*$""",
    """({auth_method}pam_faillock)"""
  ]
}
```