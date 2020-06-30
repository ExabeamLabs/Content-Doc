#### Parser Content
```Java
{
Name = unix-pam-ssh-login
  Vendor = Unix
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """pam_""", """(sshd:auth):""", """authentication""", "tty=ssh"]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """<({time}\d+\s+\w+\s+\d+\s+\d+:\d+:\d+)\s""",
    """({host}[\w\-.]+)\s+pam_unix""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+[\+\-]\d+:\d+)""",
    """({host}[^\s]*)\s*\w+:\[""",
    """\w+\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+({host}[\w\.-]+)\s+.+pam_(sss|unix)\(sshd:auth\):""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d[+-]\d+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+({host}\S+)\s+sshd\[""",
    """pam_(sss|unix)\(sshd:auth\):\s+authentication\s+({outcome}success|failure);""",
    """({event_code}ssh)""",
    """\srhost=(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+))\s""",
    """\suser=({user}[^\s>]+)""",
    """sshd\[({logon_id}\d+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```