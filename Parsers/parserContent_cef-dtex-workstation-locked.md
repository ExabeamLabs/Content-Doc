#### Parser Content
```Java
{
Name = cef-dtex-workstation-locked
  Vendor = Dtex Systems
  Product = DTEX InTERCEPT
  Lms = ArcSight
  DataType = "workstation-locked"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|SessionLocked|""" ]
  Fields = [
    """\Wstart=({time}\d+)""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """\|Dtex\|([^\|]*\|){2}(SessionActivity\|)?({event_code}[^\|]+)\|""",
  ]
  DupFields = [ "host->dest_host" ]
}
```