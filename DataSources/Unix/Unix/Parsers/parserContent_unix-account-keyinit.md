#### Parser Content
```Java
{
Name = unix-account-keyinit
  Product = Unix
  DataType = "unix-account-switch"
  Conditions = [ """[][][""", """ pam_keyinit(sudo""" ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sUser unknown:\s*(({domain}[^\\]+?)\\+)?({user}[^\\]+)\s*$""",
    """pam_keyinit\S*?:\s*({event_name}.*?change UID to ({account_used_id}\d+).*?)\s*$"""
  ]
}
```