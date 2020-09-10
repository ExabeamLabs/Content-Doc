#### Parser Content
```Java
{
Name = auditbeat-security-alert-2
  DataType = "alert"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["unauthedfileaccess""""]
  Fields = ${UnixParserTemplates.auditbeat-events.Fields}[
     """({alert_name}unauthedfileaccess)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```