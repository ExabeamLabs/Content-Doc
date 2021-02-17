#### Parser Content
```Java
{
Name = sterling-failed-logon-1
  Vendor = IBM
  Product = IBM Sterling B2B Integrator
  Lms = Syslog
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """failed in public key auth""", """sterling"""]
  Fields = [
    """\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d\+\d\d:\d\d)\s+\w+\s+sterling(?:\s-){3}""",
    """exabeam_host=({host}[^\s]+)""",  
    """userToAuth\s+({user_id}[^:]+)""",
    """({event_name}Failed login)""",
  ]
}
```