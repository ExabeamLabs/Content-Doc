#### Parser Content
```Java
{
Name = cef-unix-account-switch
  Vendor = Unix
  Lms = ArcSight
  DataType = "unix-account-switch"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix|""", """|session opened|""", """cs1=runuser""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvchost=({host}.+?)\s+(\w+=|$)""",
    """\Wsuid=({user_uid}.+?)\s+(\w+=|$)""",
    """\Wduser=({account}.+?)\s+(\w+=|$)""",
    """\Wcs1=({process_name}.+?)\s+(\w+=|$)""",
    """\Wdhost=({dest_host}.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "process_name->event_code" ]
}

{
  Name = raw-ssh-login
  Vendor = Unix
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "epoch"
  Conditions = [ "ssh", "Accepted ", " for ", " from " ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """exabeam_host=([^=]+@\s*)?({dest_host}[^\s]+)""",
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
  ]
  DupFields = ["dest_host->original_dest_host"]
}
```