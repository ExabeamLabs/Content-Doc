#### Parser Content
```Java
{
Name = s-failed-physical-access-unknown-1
  Vendor = Badge
  Product = Badge
  Lms = Direct
  DataType = "failed-physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"Access Denied"""", """No Zone Privilege""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)),"({outcome}Access Denied)","({outcome_reason}[^"]+)","({user_fullname}[^",\s]+\s{1,100}[^,]+),\s{0,100}({user}[^"\)\s]+)\s{1,100}was denied access into (Access Zone )?({location_door}[^"]+?)\s{1,100}(({direction}IN|OUT)\s{1,100})?through""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)),"({outcome}Access Denied)","({outcome_reason}[^"]+)","(CSL Vendor|({user}[^",\s]+)),\s{0,100}({user_fullname}[^"\)]+?)\s{1,100}was denied access into (Access Zone )?({location_door}[^"]+?)\s{1,100}(({direction}IN|OUT)\s{1,100})?through""",
    """"Card number\s{0,100}\(({badge_id}[^\s\)]+)""",
  ]
  DupFields = [ "outcome->event_name" ]
}
```