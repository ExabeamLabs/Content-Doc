#### Parser Content
```Java
{
Name = cef-unix-auditd-login
  Vendor = Unix
  Product = Unix Auditd
  Lms = ArcSight
  DataType = "ssh-login"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Unix|auditd|""", """|USER_AUTH\|success|""", """sshd"""]
  Fields = [
    """\srt=({time}\d+)""",
    """\soutcome=({outcome}.+?)\s+\w+=""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\saddr\\=(?:\?|({src_ip}\S+))""",
    """\shostname\\=(?:\?|(src_host)\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sshost=({src_host}\S+)""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sact=({auth}\S.+?)\s+\w+=""",
    """\sdproc=({auth_process}\S.+?)\s+\w+=""",
    """({event_code}ssh)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```