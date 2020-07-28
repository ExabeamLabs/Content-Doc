#### Parser Content
```Java
{
Name = cef-unix-ssh-disconnect
  DataType = "app-activity"
  Conditions = [ """CEF""", """Unix|Unix""", """|Received disconnect|""", """app=ssh""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
  ]
}
```