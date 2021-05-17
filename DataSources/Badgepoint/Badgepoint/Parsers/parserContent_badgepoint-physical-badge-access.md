#### Parser Content
```Java
{
Name = badgepoint-physical-badge-access
  Vendor = Badgepoint
  Product = Badgepoint
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "dd/MM/yyyy:HH:mm:ss z"
  Conditions = [ """<badgepoint_conditions>""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """([^\|]{0,2000}\|){6}({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+)""",
    """({badge_id}[^\|\s=]{1,2000})\|""",
    """([^\|]{0,2000}\|){1}({last_name}[^\|]{1,2000})\|({first_name}[^\|]{1,2000})""",
    """([^\|]{0,2000}\|){3}({location_door}[^\|]{1,2000}\|[^\|]{1,2000})""",
    """([^\|]{0,2000}\|){5}({outcome}[^\|]{1,2000})""",
  ]
}
```