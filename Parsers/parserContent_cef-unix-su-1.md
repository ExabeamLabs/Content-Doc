#### Parser Content
```Java
{
Name = cef-unix-su-1
  DataType = "unix-account-switch"
  Conditions = [ """CEF""", """Unix|Unix""", """|su succeeded|""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
     """\sduser=({account}.*?)\s+\w+="""
  ]
}
```