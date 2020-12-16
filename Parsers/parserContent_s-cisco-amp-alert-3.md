#### Parser Content
```Java
{
Name = s-cisco-amp-alert-3
  Conditions = [ """"event_type"""", """Threat Detected""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
  Fields=${CiscoParsersTemplates.s-cisco-amp-alert.Fields}[
    """file_name":"({process_name}[^\.]+\.exe)"""
  ]
}
```