#### Parser Content
```Java
{
Name = unix-failed-logon-2
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ """ <sshd> """, """<Failed password for """ ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """<({time}\d{1,100}\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\s""",
    """({event_code}ssh)""",
    """<Failed password for ({user}[^\s]+)""",
    """ from ({src_ip}[A-Fa-f:\d.]+)""",
    """ port ({src_port}\d{1,100})""",
    """\d{1,100}\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+>\s{1,100}<({dest_host}[\w\-.]+)""",
  ]
}
```