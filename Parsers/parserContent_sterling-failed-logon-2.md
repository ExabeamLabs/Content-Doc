#### Parser Content
```Java
{
Name = sterling-failed-logon-2
  Vendor = IBM
  Product = IBM Sterling B2B Integrator
  Lms = Syslog
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """[Login] Login failure for user""", """sterling"""]
  Fields = [
    """\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d\+\d\d:\d\d)\s+\w+\s+sterling(?:\s-){3}""",
    """exabeam_host=({host}[^\s]+)""",
    """Login failure for :({user_id}[^:]+)""",
    """Login failure for :[^:]+:({src_ip}[^,]+)""",
    """({event_name}Failed login)""",
  ]
}
```