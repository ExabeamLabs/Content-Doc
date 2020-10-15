#### Parser Content
```Java
{
Name = raw-ssh-login
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "ssh", "Accepted ", " for ", " from " ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """exabeam_host=([^=]+@\s*)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({dest_host}[^\s]+))""",
    """<({time}\d+\s+\w+\s+\d+\s+\d+:\d+:\d+)\s""",
    """\s(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]+)):?\s+sshd\[""",
    """\d{2}:\d{2}:\d{2}\s+({dest_host}[\w\.-]+)\s+auth\|""",
    """sshd.+?Accepted ({auth}\S+) for (({domain}[^\\:]+)\\+)?({user}[\w.'\-\\$]+)""",
    """\s+from\s+({src_ip}[:0-9a-fA-F\.]+)""",
    """\s+from\s+(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({host}[\w.\-]+) sshd ({logon_id}\d+)""",
    """({host}[\w\.\-]+):\s+sshd\[""",
    """sshd\[({logon_id}\d+)""",
    """({event_code}ssh)""",
    """\d+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\w+>\s+<({dest_host}[\w\-.]+)""",
  ]
  DupFields = ["dest_host->original_dest_host"]
}
```