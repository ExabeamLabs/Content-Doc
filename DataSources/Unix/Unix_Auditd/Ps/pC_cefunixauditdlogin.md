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
    """\srt=({time}\d{1,100})""",
    """\soutcome=({outcome}.+?)\s{1,100}\w+=""",
    """\sdvc=({host}\S+)""",
    """\sdvchost=({host}\S+)""",
    """\saddr\\=(?:\?|({src_ip}\S+))""",
    """\shostname\\=(?:\?|(src_host)\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sshost=({src_host}\S+)""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sact=({auth}\S.+?)\s{1,100}\w+=""",
    """\sdproc=({auth_process}\S.+?)\s{1,100}\w+=""",
    """({event_code}ssh)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```