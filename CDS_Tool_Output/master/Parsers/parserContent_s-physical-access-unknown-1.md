#### Parser Content
```Java
{
Name = s-physical-access-unknown-1
  Vendor = Unknown
  Product = Unknown
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"Card Event"""", """"Card Exit Granted"""", """Access Zone""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d+\/\d+\/\d\d\d\d\s+\d+:\d+:\d+\s+(AM|PM|am|pm)),"Card Event","({outcome}[^"]+)","({user_fullname}[^",]+)(,\s*({user}[^"]+?))?\s+exited to Access Zone\s+({location_door}[^"]+?)\s+(({direction}IN|OUT)\s+)?through""",
    """"Card number\s*\(({badge_id}[^\s\)]+)""",
  ]
  DupFields = [ "outcome->event_name" ]
}
```