#### Parser Content
```Java
{
Name = cef-unix-local-logon
  DataType = "local-logon"
  Conditions = [ """CEF""", """Unix|Unix""", """|Started Session|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
    """of user ({user}[^\s\.]+)""",
  ]
}
```