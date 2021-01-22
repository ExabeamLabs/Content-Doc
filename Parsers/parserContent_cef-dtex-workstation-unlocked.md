#### Parser Content
```Java
{
Name = cef-dtex-workstation-unlocked
  Vendor = Dtex
  Product = Dtex
  Lms = ArcSight
  DataType = "workstation-unlocked"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|SessionUnlocked|""" ]
  Fields = [
    """\Wstart=({time}\d+)""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """\|Dtex\|([^\|]*\|){2}(SessionActivity\|)?({event_code}[^\|]+)\|""",
  ]
  DupFields = [ "host->dest_host" ]
}
```