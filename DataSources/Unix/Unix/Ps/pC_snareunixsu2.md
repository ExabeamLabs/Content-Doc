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
    """exabeam_host=(::ffff:)?({host}[\w.\-]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
    """\d\d:\d\d\s{0,100}(::ffff:)?({host}[\w\.\-]{1,2000})?\s{0,100}({event_code}su):\s(?:\[[^]]{1,2000}\])?\s{0,100}\'su ({account}[^']{1,2000})\' succeeded for\s{1,100}({user}[\w\.]{1,2000})\s{1,100}on""",
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-.]{1,2000})))\s"""
  ]
}
}
```