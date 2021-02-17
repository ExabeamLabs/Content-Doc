#### Parser Content
```Java
{
Name = auditbeat-security-alert-4
  DataType = "alert"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["power_abuse""""]
  Fields = ${UnixParserTemplates.auditbeat-events.Fields}[
     """({alert_name})power_abuse""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```