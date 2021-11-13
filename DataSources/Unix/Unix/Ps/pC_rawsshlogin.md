#### Parser Content
```Java
{
Name = raw-ssh-login
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ ssh2""", """Accepted """, """ for """, """ from """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(gcs-topic|([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))))""",
    """"host":"(::ffff:)?({dest_host}({host}[^"]{1,2000}))""""
    """"host":\{"name":"(::ffff:)?({dest_host}({host}[^"]{1,2000}))""""
    """<({time}\d\d\d\d\s{1,100}\w{3}\s{1,100}\d\d\s{1,100}\d\d:\d\d:\d\d)\s""",
    """\d\d:\d\d:\d\d \d\d\d\d (::ffff:)?({host}({dest_host}[^\s]{1,2000}))""",
    """\s(::ffff:)?({host}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]{1,2000})):?\s{1,100}sshd\[""",
    """\d{2}:\d{2}:\d{2}\s{1,100}(::ffff:)?({dest_host}[\w\.-]{1,2000})\s{1,100}auth\|""",
    """Accepted ({auth}\S{1,2000}) for (({domain}[^\\:]{1,2000})\\+)?({user}[\w.'\-\\$]{1,2000})(\s|$)""",
    """Accepted ({auth}\S{1,2000}) for (({user}[^\s@]{1,2000}?)@({domain}[^\s]{1,2000}))""",
    """\s{1,100}from\s{1,100}(::ffff:)?({src_ip}[:0-9a-fA-F\.]{1,2000})""",
    """\s{1,100}from\s{1,100}(::[\w]{1,2000}:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """(::ffff:)?({host}[\w.\-]{1,2000}) sshd ({logon_id}\d{1,100})""",
    """(::ffff:)?({host}[\w\.\-]{1,2000}):\s{1,100}sshd\[""",
    """sshd\[({logon_id}\d{1,100})""",
    """({event_code}ssh)""",
    """\d\d\d\d\s{1,100}\w{3}\s{1,100}\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}\w{1,2000}>\s{1,100}<(::ffff:)?({dest_host}[\w\-.]{1,2000})""",
    """"computer_name":"(::ffff:)?({host}({dest_host}[\w\-.]{1,2000}))""""
  ]
  DupFields = ["dest_host->original_dest_host"]


}
```