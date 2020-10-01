#### Parser Content
```Java
{
Name = cef-sophos-security-alert-18
  Conditions = [ """CEF:""", """ext_type=Event::Endpoint::WebControlViolation""" ]
  Fields=${SophosParserTemplates.cef-sophos-security-alert-1.Fields}[
    """"name"*:\s*"*'({malware_url}[^"\'\s]+)'\s+blocked due to""",
    """"name"*:"*'({alert_name}[^"]+)\s"""
  ]
}
```