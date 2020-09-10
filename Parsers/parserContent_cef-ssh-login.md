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
    """exabeam_EventTime=({eventtime}\d+)""",
    """\srt=({time}\d+)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sdvc(host)?=({host}[^\s]+)""",
    """ dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ dhost=({dest_host}[^\s]+)""",
    """ cs4=({logon_id}\d+)""",
    """\|Accepted ({auth}.+?)\|""",
    """({event_code}ssh)"""
  ]
}
```