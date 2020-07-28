#### Parser Content
```Java
{
Name = cef-unix-ssh-fail
  DataType = "ssh-login"
  Conditions = [ """CEF""", """Unix|Unix""", """|failed login attempt|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
     """\sduser=({user}.*?)\s+\w+="""
  ]
}
```