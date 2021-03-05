#### Parser Content
```Java
{
Name = snare-unix-su-1
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "su: (to"," on " ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d:\d\d\s*({host}[\w\.\-]+)?\s*({event_code}su):\s+\(to\s+({account}[^)]+)\)\s+({user}[\w\.]+)\s+on"""
  ]
DupFields=["host->dest_host"]
}
```