#### Parser Content
```Java
{
Name = s-cisco-amp-alert-10
  Conditions = [ """"event_type"""", """"Cloud IOC""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
  Fields=${CiscoParsersTemplates.s-cisco-amp-alert.Fields}[
    """"short_description":"({alert_name}[^"]+)""",
  ]
}
```