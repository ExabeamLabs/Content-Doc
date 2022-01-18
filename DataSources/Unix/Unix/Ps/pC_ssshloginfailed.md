#### Parser Content
```Java
{
Name = s-ssh-login-failed
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ sshd[""", """nvalid user """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({host}[\w\.-]{1,2000}):?\s{1,100}sshd\[""",
    """({failure_reason}(i|I)nvalid user)\s{1,100}(({domain}.+?)\\+)?({user}\S+)""",
    """\sfrom\s{1,100}(::[\w]{1,2000}:)?(({src_ip}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1))|({src_host}[\w\.\-]{1,2000}))\s""",
    """sshd\[({logon_id}\d{1,100})""",
    """({event_code}ssh)""",
  ]
  DupFields = [ "host->dest_host" ]


}
```