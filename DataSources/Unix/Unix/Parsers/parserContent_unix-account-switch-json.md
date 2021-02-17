#### Parser Content
```Java
{
Name = unix-account-switch-json
  Product = Unix
  DataType = "unix-account-switch"
  Conditions = [ """"ident":"sudo""", """pam_unix(sudo:session): session""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """session (opened|closed) for user ({account}[^\s"]+)""",
    """\(uid=({user_id}\d+)\)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```