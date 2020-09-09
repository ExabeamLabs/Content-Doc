#### Parser Content
```Java
{
Name = admanager-activity
  Vendor = ManageEngine
  Product = ADmanager
  Lms = Direct
  DataType = "member-removed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ADMP""", """Status=""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s*({host}[^\s]+)""",
    """\[Status=({status}[^]]+)\]""",
    """\[TechnicianName=(\([^[\)]+\)\s*)?({user}[^]]+)\]""",
    """\[Task=({activity}[^]]+)\]""",
    """\[ACTION=({action}[^]]+)\]""",
    """\[accountExpires=({account}[^]]+)\]""",
    """\[Template Name=({event_name}[^]]+)\]""",
    """\[Object Name=({object}[^]]+)\]""",
    """\[Domain Name=({domain_name}[^]]+)\]""",
    """\[memberOf=\[({group_name}[^]]+)]]""",
    """\[Object Name=(\([^[\)]+\)\s*)?({account}[^]]+)\]""",
  ]
}
```