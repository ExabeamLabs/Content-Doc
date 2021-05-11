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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """([^\|]*\|){6}({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+)""",
    """({badge_id}[^\|\s=]+)\|""",
    """([^\|]*\|){1}({last_name}[^\|]+)\|({first_name}[^\|]+)""",
    """([^\|]*\|){3}({location_door}[^\|]+\|[^\|]+)""",
    """([^\|]*\|){5}({outcome}[^\|]+)""",
  ]
}
```