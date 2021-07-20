#### Parser Content
```Java
{
Name = cef-576
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-privileged-access"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""","""|Security:576|""" ]
  Fields = [ 
    """({event_name}Special privileges assigned to new logon)""",
    """({event_code}576)""",
    """\srt=({time}\d{1,100})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\sduid=\([^,]{1,2000}
```