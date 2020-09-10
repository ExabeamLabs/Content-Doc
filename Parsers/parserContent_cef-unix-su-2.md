#### Parser Content
```Java
{
Name = cef-unix-su-2
  DataType = "unix-account-switch"
  Conditions = [ """CEF""", """Unix|Unix""", """|session closed|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
     """\sduser=({account}.*?)\s+\w+="""
  ]
}
```