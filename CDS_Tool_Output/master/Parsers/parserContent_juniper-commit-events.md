#### Parser Content
```Java
{
Name = juniper-commit-events
  Vendor = Juniper
  Lms = Direct
  DataType = "config-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ mgd """, """ UI_COMMIT """, """ requested """ ]
  Fields = [
    """<\d+>\d+\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d(\+|\-)\d\d:\d\d)""",
    """({host}\S+)\s+mgd\s""",
    """\sUser '({user}[^']+)' requested '({activity}[^']+)' """
  ]
  DupFields = [ "host->dest_host" ]
}
```