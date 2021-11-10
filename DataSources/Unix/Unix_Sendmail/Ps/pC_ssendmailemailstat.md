#### Parser Content
```Java
{
Name = s-sendmail-email-stat
  Vendor = Unix
  Product = Unix Sendmail
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"  
  Conditions = [ """ dsn=""", """ delay=""", """ relay=""", """ stat=""" ]
  Fields = [
    """:\s(::ffff:)?({host}[^\s:]{1,2000}):*\s{1,100}to=""",
    """\w{1,2000} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (Message forwarded from )?(::ffff:)?({host}[\w.\-]{1,2000}):? \S+ ({alert_id}\S{1,2000}?):""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}(::ffff:)?({host}[\w.\-]{1,2000})\s{1,100}\S{1,2000}\s{1,100}({alert_id}\S{1,2000}?):""",
    """({host}[\w\.\-]{1,2000})\ssendmail""",
    """\sstat=({outcome}\w{1,2000})""",
    """to=({recipients}<({recipient}[^@]{1,2000}@[^>,]{1,2000})[^=]{1,2000}?),\s{1,100}\w{1,2000}=""",
    """\srelay=({dest_host}[^\s\[]{1,2000}?)\.?\s{0,100}\[({dest_ip}[a-fA-F:\d.]{1,2000})?""",
    """({bytes}\d{1,100})\sbytes"""
  ]
}
}
```