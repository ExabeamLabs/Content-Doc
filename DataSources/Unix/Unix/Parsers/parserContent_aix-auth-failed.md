#### Parser Content
```Java
{
Name = aix-auth-failed
  Vendor = Unix
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """(dsepam:auth):""", """authentication failure;""" ]
  Fields = [
    """({time}\w+ \d+ \d\d:\d\d:\d\d)\s+({host}\S+)\s+\S+\s+\S+\(dsepam:auth\)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\suser=({user}.+?)(\s+\w+=|\s*$)""",
  ]
}
```