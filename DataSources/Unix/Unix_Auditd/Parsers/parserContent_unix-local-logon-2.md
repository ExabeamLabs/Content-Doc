#### Parser Content
```Java
{
Name = unix-local-logon-2
  DataType = "local-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"type":"LOGIN"""", """CEF:""", """|Skyformation|SkyFormation""", """Cloud Apps Security|""", """|audit-event|""" ]
  Fields = ${UnixParserTemplates.unix-template.Fields}[
    """\spid\\?=({process_id}[^\s]+)\s\w+"""
  ]
}
```