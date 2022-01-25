#### Parser Content
```Java
{
Name = s-sendmail-email-from
  Vendor = Unix
  Product = Unix Sendmail
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ msgid=""", """ from=""", """ nrcpts=""" ]
  Fields = [
    """exabeam_host=(::ffff:)?({host}[\w.\-]{1,2000})""",
    """sendmail\S*:\s{1,100}({alert_id}\S+?):\s""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s{1,100}from=<?({sender}[^@=<>,]{1,2000}@[^\s@=<>,]{1,2000})""",
    """\ssize=({bytes}\d{1,100})""",
    """\snrcpts=({num_recipients}\d{1,100})""",
    """\smsgid=<({return_path}[^>]{1,2000})>""",
    """\sproto=({protocol}[^,]{1,2000})""",
    """\srelay=(::ffff:)?({dest_host}[\w\-.]{1,2000})\s{0,100}\[(::ffff:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
  ]
  DupFields = [ "sender->user_email" ]


}
```