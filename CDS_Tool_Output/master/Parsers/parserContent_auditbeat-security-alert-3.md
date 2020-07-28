#### Parser Content
```Java
{
Name = auditbeat-security-alert-3
  DataType = "alert"
  Conditions = ["""logstash-auditbeat""", """"process"""", """"tags":["recon""""]
  Fields = ${UnixParserTemplates.auditbeat-events.Fields}[
     """({alert_name}recon)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```