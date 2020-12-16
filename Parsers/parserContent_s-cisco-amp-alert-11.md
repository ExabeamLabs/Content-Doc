#### Parser Content
```Java
{
Name = s-cisco-amp-alert-11
  Conditions = [ """"event_type"""", """"Policy Update Failure"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
  Fields=${CiscoParsersTemplates.s-cisco-amp-alert.Fields}[
    """file_name":"({process_name}[^\.]+\.exe)"""
  ]
}
```