#### Parser Content
```Java
{
Name = s-ssh-login-failed
  Vendor = Unix
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ sshd[""", """nvalid user """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """({host}[\w\.-]+):?\s+sshd\[""",
    """({failure_reason}(i|I)nvalid user)\s+(({domain}.+?)\\+)?({user}\S+)""",
    """\sfrom\s+(::[\w]+:)?(({src_ip}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1))|({src_host}[\w\.\-]+))\s""",
    """sshd\[({logon_id}\d+)""",
    """({event_code}ssh)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```