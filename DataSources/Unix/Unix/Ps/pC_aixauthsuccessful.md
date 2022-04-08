#### Parser Content
```Java
{
Name = aix-auth-successful
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """(dsepam:auth):""", """authentication success;""" ]
  Fields = [
    """\d\d:\d\d:\d\d(\.\S+)?\s({host}[^\s]{1,2000})""",
    """({time}\w+ \d{1,100} \d\d:\d\d:\d\d(\.\S+)?)\s{1,100}({host}\S+)\s{1,100}\S+\s{1,100}\S+\(dsepam:auth\)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\suser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]


}
```