#### Parser Content
```Java
{
Name = auditbeat-security-alert
  DataType = "alert"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["susp_activity""""]
  Fields = ${UnixParserTemplates.auditbeat-events.Fields}[
     """({alert_name}susp_activity)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```