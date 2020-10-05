#### Parser Content
```Java
{
Name = cef-sophos-security-alert-31
  Conditions = [ """CEF:""", """type=Event::Endpoint::DataLossPreventionAutomaticallyAllowed""" ]
  Fields=${SophosParserTemplates.cef-sophos-security-alert-1.Fields}[
    """"name"*:"*({alert_name}[^"]+).\sUsername:"""
  ]
}
```