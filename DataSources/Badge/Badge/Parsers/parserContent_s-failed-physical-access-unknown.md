#### Parser Content
```Java
{
Name = s-failed-physical-access-unknown
  Vendor = Badge
  Product = Badge
  Lms = Direct
  DataType = "failed-physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"Access Denied"""", """"Unauthorised Card"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)),"({outcome}Access Denied)","({outcome_reason}[^"]+)","[^"]+? into\s{1,100}(Access Zone\s{0,100})?(\([^\)]*\)\s{0,100})?({location_door}[^"]+?)\s{1,100}(({direction}IN|OUT)\s{1,100})?through""",
    """"Card number\s{0,100}\(({badge_id}[^\s\)]+)""",
  ]
  DupFields = [ "outcome->event_name" ]
}
```