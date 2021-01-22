#### Parser Content
```Java
{
Name = s-failed-physical-access-unknown-1
  Vendor = Unknown
  Lms = Direct
  DataType = "failed-physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"Access Denied"""", """No Zone Privilege""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d+\/\d+\/\d\d\d\d\s+\d+:\d+:\d+\s+(AM|PM|am|pm)),"({outcome}Access Denied)","({outcome_reason}[^"]+)","({user_fullname}[^",\s]+\s+[^,]+),\s*({user}[^"\)\s]+)\s+was denied access into (Access Zone )?({location_door}[^"]+?)\s+(({direction}IN|OUT)\s+)?through""",
    """({time}\d+\/\d+\/\d\d\d\d\s+\d+:\d+:\d+\s+(AM|PM|am|pm)),"({outcome}Access Denied)","({outcome_reason}[^"]+)","(CSL Vendor|({user}[^",\s]+)),\s*({user_fullname}[^"\)]+?)\s+was denied access into (Access Zone )?({location_door}[^"]+?)\s+(({direction}IN|OUT)\s+)?through""",
    """"Card number\s*\(({badge_id}[^\s\)]+)""",
  ]
  DupFields = [ "outcome->event_name" ]
}
```