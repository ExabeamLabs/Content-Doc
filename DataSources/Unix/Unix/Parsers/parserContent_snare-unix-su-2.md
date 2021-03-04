#### Parser Content
```Java
{
Name = snare-unix-su-2
  Vendor = Unix
  Lms = Splunk
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "succeeded for"," su:" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\d\d:\d\d\s*({host}[\w\.\-]+)?\s*({event_code}su):\s(?:\[[^]]+\])?\s*\'su ({account}[^']+)\' succeeded for\s+({user}[\w\.]+)\s+on"""
  ]
DupFields=["host->dest_host"]
}
```