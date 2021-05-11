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
    """\srt=({time}\d{1,100})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\sduid=\([^,]+,({logon_id}[^\)]+)""",
    """\sdntdom=({domain}.+?)\s{1,100}\w+=""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdhost=({dest_host}.+?)\s{1,100}\w+=""",
    """\sdst=({dest_ip}.+?)\s{1,100}\w+=""",
    """\sdpriv=({privileges}.+?)\s{1,100}\w+=""",
    """\sdvchost=({host}.+?)\s{1,100}\w+=""",
    """categoryOutcome=\/({outcome}[^\s]+)""",
  ]
}
```