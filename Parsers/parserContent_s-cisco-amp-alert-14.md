#### Parser Content
```Java
{
Name = s-cisco-amp-alert-14
  Conditions = [ """"event_type"""", """"Cloud Recall Detection of False Negative"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
  Fields=${CiscoParsersTemplates.s-cisco-amp-alert.Fields}[
    """file_name":"({process_name}[^\.]+\.exe)"""
  ]
}
```