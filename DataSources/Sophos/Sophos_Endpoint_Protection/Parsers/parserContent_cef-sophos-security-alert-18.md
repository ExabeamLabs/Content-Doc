#### Parser Content
```Java
{
Name = cef-sophos-security-alert-18
  Conditions = [ """CEF:""", """ext_type=Event::Endpoint::WebControlViolation""" ]
  Fields=${SophosParserTemplates.cef-sophos-security-alert-1.Fields}[
    """"name"{0,20}:\s{0,100}"{0,20}'({malware_url}[^"\'\s]+)'\s{1,100}blocked due to""",
    """"name"{0,20}:"{0,20}'({alert_name}[^"]+)\s"""
  ]
}
```