#### Parser Content
```Java
{
Name = cef-576
  Vendor = Microsoft
  Product = Windows
  Lms = ArcSight
  DataType = "windows-privileged-access"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Security:576|""" ]
  Fields = [ 
    """({event_name}Special privileges assigned to new logon)""",
    """({event_code}576)""",
    """\srt=({time}\d{1,100})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\sduid=\([^,]{1,2000},({logon_id}[^\)]{1,2000})""",
    """\sdntdom=({domain}.+?)\s{1,100}\w+=""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdhost=({dest_host}.+?)\s{1,100}\w+=""",
    """\sdst=({dest_ip}.+?)\s{1,100}\w+=""",
    """\sdpriv=({privileges}.+?)\s{1,100}\w+=""",
    """\sdvchost=({host}.+?)\s{1,100}\w+=""",
    """\scategoryOutcome=\/*({outcome}[^\s]{1,2000})""", 
  ]
}
```