#### Parser Content
```Java
{
Name = unix-ssh-login-failed-json-1
  Product = Unix
  DataType = "ssh-login"
  Conditions = [ """"ident":"sshd""", """fatal: Unable to negotiate""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """Unable to negotiate with ({src_ip}[a-fA-F\d.:]+)""",
  ]
}
```