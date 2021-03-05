#### Parser Content
```Java
{
Name = unix-pam-ssh-login
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS z"
  Conditions = [ """pam_""", """(sshd:auth):""", """authentication""", "tty=ssh"]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\w+\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+({host}[\w\.-]+)\s+.+pam_(sss|unix)\(sshd:auth\):""",
    """pam_(sss|unix)\(sshd:auth\):\s+authentication\s+({outcome}success|failure);""",
    """({event_code}ssh)""",
    """\srhost=(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}[\w\-.]+))\s""",
    """\suser=({user}[^\s>"]+)""",
    """sshd\[({logon_id}\d+)""",
     """\d+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\w+>\s+<({dest_host}[\w\-.]+)""",
    """"+_time"+:"+({time}[^"]+)"+""",
  ]
}
```