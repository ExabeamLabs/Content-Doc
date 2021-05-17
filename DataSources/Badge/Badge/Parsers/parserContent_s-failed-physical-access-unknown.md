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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)),"({outcome}Access Denied)","({outcome_reason}[^"]{1,2000})","[^"]{1,2000}? into\s{1,100}(Access Zone\s{0,100})?(\([^\)]{0,2000}\)\s{0,100})?({location_door}[^"]{1,2000}?)\s{1,100}(({direction}IN|OUT)\s{1,100})?through""",
    """"Card number\s{0,100}\(({badge_id}[^\s\)]{1,2000})""",
  ]
  DupFields = [ "outcome->event_name" ]
}
```