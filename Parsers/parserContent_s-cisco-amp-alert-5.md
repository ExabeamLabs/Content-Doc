#### Parser Content
```Java
{
Name = s-cisco-amp-alert-5
  Conditions = [ """"event_type"""", """"Vulnerable Application Detected"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
  DupFields = [ "alert_type->alert_name" ]
  Fields=${CiscoParsersTemplates.s-cisco-amp-alert.Fields}[
    """file_name":"({process_name}[^\.]+\.exe)"""
  ]
}
```