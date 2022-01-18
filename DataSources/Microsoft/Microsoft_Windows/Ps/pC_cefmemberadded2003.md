#### Parser Content
```Java
{
Name = cef-member-added-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-member-added"
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|Microsoft Windows|""", """|Security:6""", """Security Enabled""", """Group Member Added""" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]{1,2000} Group Member Added)""",
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """Security:({event_code}\d{1,100})""",
    """\|Security Enabled ({group_type}\w+)""",
    """\srt=({time}\d{1,100})""",
    """\ssntdom=({domain}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\ssuid=\([^,]{1,2000

}
```