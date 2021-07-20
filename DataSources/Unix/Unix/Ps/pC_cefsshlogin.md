#### Parser Content
```Java
{
Name = cef-ssh-login
  Vendor = Unix
  Product = Unix
  Lms = ArcSight
  DataType = "ssh-login"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix|""", """|Accepted""" ]
  Fields = [
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\srt=({time}\d{1,100})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdvc(host)?=({host}[^\s]{1,2000})""",
    """ dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ dhost=({dest_host}[^\s]{1,2000})""",
    """ cs4=({logon_id}\d{1,100})""",
    """\|Accepted ({auth}.+?)\|""",
    """({event_code}ssh)"""
  ]
}
```