#### Parser Content
```Java
{
Name = cef-snare-576
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-privileged-access"
  TimeFormat = "epoch"
  Conditions = [ """|Snare|""","""|Security:576|""" ]
  Fields = [
    """({event_name}Special privileges assigned to new logon)""",
    """({event_code}576)""",
    """\srt=({time}\d+)""",
    """\ssuser=({user}.+?)\s+\w+=""",
    """\sduid=\([^,]+,({logon_id}[^\)]+)""",
    """\sdntdom=({domain}.+?)\s+\w+=""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sdhost=({dest_host}.+?)\s+\w+=""",
    """\sdst=({dest_ip}.+?)\s+\w+=""",
    """\sdpriv=({privileges}.+?)\s+\w+=""",
    """\sdvchost=({host}.+?)\s+\w+=""",
    """categoryOutcome=\/({outcome}[^\s]+)""",
  ]
}
```