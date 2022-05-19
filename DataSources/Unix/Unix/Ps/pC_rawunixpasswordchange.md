#### Parser Content
```Java
{
Name = raw-unix-password-change
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """pam_unix(passwd:chauthtok):""", "password changed for" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(::ffff:)?(gcs-topic|({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000}))))""",
    """"agent_hostname":"(::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^"]{1,200})))"""",
    """\d\d:\d\d:\d\dZ? (::ffff:)?({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w.\-]{1,2000})))""",
    """password changed for ({target_user}.+?)\s{0,20}("|$)""",
  ]


}
```