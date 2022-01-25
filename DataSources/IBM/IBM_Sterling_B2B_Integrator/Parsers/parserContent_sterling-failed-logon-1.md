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
    """\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d\+\d\d:\d\d)\s{1,100}\w+\s{1,100}sterling(?:\s-){3}""",
    """exabeam_host=({host}[^\s]{1,2000})""",  
    """userToAuth\s{1,100}({user_id}[^:]{1,2000})""",
    """({event_name}Failed login)""",
  ]
}
```