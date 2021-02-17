#### Parser Content
```Java
{
Name = json-okta-security-alert
  DataType = "security-alert"
  Conditions = [ """"security.threat.detected"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """"severity"+:"+({alert_severity}[^",]+)""",
    """({alert_type}application-action)"""
  ]
  DupFields = [ "event_name->alert_name" ]
}
```