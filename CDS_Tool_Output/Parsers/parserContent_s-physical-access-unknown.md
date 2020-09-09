#### Parser Content
```Java
{
Name = s-physical-access-unknown
  Vendor = Unknown
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"Card Event"""", """"Door Access Granted"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d+\/\d+\/\d\d\d\d\s+\d+:\d+:\d+\s+(AM|PM|am|pm)),"Card Event","({outcome}[^"]+)","(({user}[^",\s]+)[^,]*,\s*)?({user_fullname}[^"]+?)\s+was granted entry into\s+({location_door}[^"]+?)\s+(({direction}IN|OUT)\s+)?through""",
    """"Card number\s*\(({badge_id}[^\s\)]+)""",
  ]
  DupFields = [ "outcome->event_name" ]
}
```