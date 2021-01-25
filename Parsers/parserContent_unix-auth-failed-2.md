#### Parser Content
```Java
{
Name = unix-auth-failed-2
  DataType = "authentication-failed"
  Conditions = [ """[][][""", """ pam_unix(sudo""", """ authentication failure""" ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sruser=(|({account}.+?))(\s+\w+=|\s*$)""",
    """\suser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\suid=(|({user_id}.+?))(\s+\w+=|\s*$)""",
  ]
}
```