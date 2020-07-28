#### Parser Content
```Java
{
Name = s-failed-physical-access-unknown
  Vendor = Unknown
  Product = Unknown
  Lms = Direct
  DataType = "failed-physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"Access Denied"""", """"Unauthorised Card"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d+\/\d+\/\d\d\d\d\s+\d+:\d+:\d+\s+(AM|PM|am|pm)),"({outcome}Access Denied)","({outcome_reason}[^"]+)","[^"]+? into\s+(Access Zone\s*)?(\([^\)]*\)\s*)?({location_door}[^"]+?)\s+(({direction}IN|OUT)\s+)?through""",
    """"Card number\s*\(({badge_id}[^\s\)]+)""",
  ]
  DupFields = [ "outcome->event_name" ]
}
```