#### Parser Content
```Java
{
Name = unix-failed-logon-1
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ """ <sshd> """, """<Invalid user """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """<({time}\d{1,100}\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\s""",
    """({event_code}ssh)""",
    """<Invalid user ({user}[^\s]{1,2000})""",
    """ from ({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\d{1,100}\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+>\s{1,100}<({dest_host}[\w\-.]{1,2000})""",
  ]
}
```