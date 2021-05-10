#### Parser Content
```Java
{
Name = snare-unix-su-1
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """su: (to""",""" on """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(::ffff:)?({host}[\w.\-]+)""",
    """\d\d:\d\d\s{1,100}(::ffff:)?({host}[\w\.\-]+)?\s{0,100}({event_code}su):\s{1,100}\(to\s{1,100}({account}[^)]+)\)\s{1,100}({user}[\w\.]+)\s{1,100}on""",
    """:\d\d:\d\d\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.-]+))\s""",
  ]
}
```