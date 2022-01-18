#### Parser Content
```Java
{
Name = cef-540
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-540"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""", """|Security:540|""" ]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({event_code}540)""",
    """\srt=({time}\d{1,100})""",
    """\ssproc=({auth_process}.+?)\s{1,100}\w+=""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sduid=\([^,]{1,2000

}
```