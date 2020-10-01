#### Parser Content
```Java
{
Name = cef-sophos-security-alert-20
  Conditions = [ """CEF:""", """ext_type=Event::Endpoint::UserAutoCreated""" ]
   Fields=${SophosParserTemplates.cef-sophos-security-alert-1.Fields}[
    """"name"*:"*({alert_name}[^":]+)"""
  ]
}
```