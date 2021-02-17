#### Parser Content
```Java
{
Name = unix-ssh-login-failed-json
  DataType = "ssh-login"
  Conditions = [ """"ident":"sshd""", """nvalid user""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """(I|i)nvalid user (({domain}[^\\:]+)\\+)?({user}[\w.'\-\\$]+)""",
    """from ({src_ip}[a-fA-F\d.:]+)""",
    """\s+from\s+(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```