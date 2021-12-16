#### Parser Content
```Java
{
Name = unix-pam-ssh-login
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """pam_""", """(sshd:auth):""", """authentication""", """tty=ssh""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w{3}\s{1,100}\d{1,2}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\.-]{1,2000})\s{1,100}[^=]{1,2000}?pam_(sss|unix)\(sshd:auth\):""",
    """timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """pam_(sss|unix)\(sshd:auth\):\s{1,100}authentication\s{1,100}({outcome}success|failure);""",
    """({event_code}ssh)""",
    """\srhost=(?:({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[\w\-.]{1,2000}))\s""",
    """\suser=(({domain}[^\\=]{1,200})\\{1,25})?({user}[^\s>="]{1,2000})""",
    """sshd\[({logon_id}\d{1,100})""",
    """\d{4}\s{1,100}\w{3}\s{1,100}\d{1,2}\s{1,100}\d\d:\d\d:\d\d\s{1,100}\w{1,2000}>\s{1,100}<({dest_host}[\w\-.]{1,2000})""",
    """"{1,20}_time"{1,20}:"{1,20}({time}[^"]{1,2000})"{1,20}""",
    """\suid=({user_id}[^\s]{1,2000})\s"""
  ]


}
```