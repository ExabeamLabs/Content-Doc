#### Parser Content
```Java
{
Name = cef-sophos-dlp-alert-7
  DataType = "dlp-alert"
  Conditions = [ """CEF:""", """type=Event::Endpoint::DataLossPreventionAutomaticallyAllowed""" ]
  Fields=${SophosParserTemplates.cef-sophos-security-alert-1.Fields}[
    """"name"{0,20}:"{0,20}({alert_name}[^"]+).\sUsername:"""
  ]
}
```