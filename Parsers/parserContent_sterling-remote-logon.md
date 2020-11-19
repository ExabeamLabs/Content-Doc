#### Parser Content
```Java
{
Name = sterling-remote-logon
  Vendor = IBM
  Product = IBM Sterling B2B Integrator
  Lms = Syslog
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """[Login]: User session created for""", """sterling"""]
  Fields = [
    """\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d\+\d\d:\d\d)\s+\w+\s+sterling(?:\s-){3}""",
    """exabeam_host=({host}[^\s]+)""",
    """User session created for\s+({user_id}[^,]+)""",
    """({event_name}User session created)""",
  ]
}
```