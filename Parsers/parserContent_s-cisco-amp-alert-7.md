#### Parser Content
```Java
{
Name = s-cisco-amp-alert-7
  Conditions = [ """"event_type"""", """"Executed malware"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
  Fields=${CiscoParsersTemplates.s-cisco-amp-alert.Fields}[
    """file_name":"({process_name}[^\.]+\.exe)"""
  ]
}
```