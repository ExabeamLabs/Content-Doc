#### Parser Content
```Java
{
Name = snare-unix-su-2
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "succeeded for"," su:" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_host=([^=]+@\s{0,100})?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({dest_host}[^\s]+))""",
    """\d\d:\d\d\s{0,100}({host}[\w\.\-]+)?\s{0,100}({event_code}su):\s(?:\[[^]]+\])?\s{0,100}\'su ({account}[^']+)\' succeeded for\s{1,100}({user}[\w\.]+)\s{1,100}on"""
  ]
}
```