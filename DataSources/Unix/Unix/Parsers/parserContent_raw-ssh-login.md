#### Parser Content
```Java
{
Name = raw-ssh-login
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ssh""", """Accepted """, """ for """, """ from """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?(::ffff:)?({host}[^\s]+)""",
    """exabeam_host=([^=]+@\s{0,100})?(::ffff:)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({dest_host}[^\s]+))""",
    """<({time}\d{1,100}\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\s""",
    """\d\d:\d\d:\d\d \d\d\d\d ({host}[^\s]+)""",
    """\d\d:\d\d:\d\d \d\d\d\d ({dest_host}[^\s]+)""",
    """\s(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]+)):?\s{1,100}sshd\[""",
    """\d{2}:\d{2}:\d{2}\s{1,100}(::ffff:)?({dest_host}[\w\.-]+)\s{1,100}auth\|""",
    """Accepted ({auth}\S+) for (({domain}[^\\:]+)\\+)?({user}[\w.'\-\\$]+)(\s|$)""",
    """\s{1,100}from\s{1,100}(::ffff:)?({src_ip}[:0-9a-fA-F\.]+)""",
    """\s{1,100}from\s{1,100}(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """(::ffff:)?({host}[\w.\-]+) sshd ({logon_id}\d{1,100})""",
    """(::ffff:)?({host}[\w\.\-]+):\s{1,100}sshd\[""",
    """sshd\[({logon_id}\d{1,100})""",
    """({event_code}ssh)""",
    """\d{1,100}\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+>\s{1,100}<(::ffff:)?({dest_host}[\w\-.]+)""",
  ]
  DupFields = ["dest_host->original_dest_host"]
}
```