#### Parser Content
```Java
{
Name = cef-unix-local-logon-1
  DataType = "local-logon"
  Conditions = [ """CEF""", """Unix|Unix""", """|Starting Session|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
    """of user ({user}[^\s\.]+)""",
  ]
}
```