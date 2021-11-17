#### Parser Content
```Java
{
Name = raw-unix-su
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "session opened for user","su:", """(uid=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?(gcs-topic|({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000}))))""",
    """"agent_hostname":"(::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^"]{1,200})))"""",
    """\d\d:\d\d:\d\d (::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000})))\s{1,100}su(:|\[)""",
    """({event_code}su):.+?for user ({account}[^\s]{1,2000}) by ({user}[\w\.]{1,2000})?\(uid=({user_uid}\d{1,100})\)"""
  ]


}
```