#### Parser Content
```Java
{
Name = unix-ssh-login-json
  Product = Unix
  DataType = "ssh-login"
  Conditions = [ """"ident":"sshd""", """Accepted publickey for""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """Accepted ({auth}\S+) for (({domain}[^\\:]+)\\+)?({user}[\w.'\-\\$]+)""",
    """from ({src_ip}[a-fA-F\d.:]+)""",
    """\s+from\s+(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```