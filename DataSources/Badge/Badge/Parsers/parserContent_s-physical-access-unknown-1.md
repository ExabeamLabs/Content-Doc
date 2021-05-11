#### Parser Content
```Java
{
Name = s-physical-access-unknown-1
  Vendor = Badge
  Product = Badge
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"Card Event"""", """"Card Exit Granted"""", """Access Zone""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)),"Card Event","({outcome}[^"]+)","({user_fullname}[^",]+)(,\s{0,100}({user}[^"]+?))?\s{1,100}exited to Access Zone\s{1,100}({location_door}[^"]+?)\s{1,100}(({direction}IN|OUT)\s{1,100})?through""",
    """"Card number\s{0,100}\(({badge_id}[^\s\)]+)""",
  ]
  DupFields = [ "outcome->event_name" ]
}
```