#### Parser Content
```Java
{
Name = cef-dtex-local-logon
  Vendor = Dtex Systems
  Product = DTEX InTERCEPT
  Lms = ArcSight
  DataType = "local-logon"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|SessionActivity|SessionLogon|""" ]
  Fields = [
    """\Wstart=({time}\d+)""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """\WUser_Name=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)\s""",
    """\|Dtex\|([^\|]*\|){2}(SessionActivity\|)?({event_code}[^\|]+)\|""",
  ]
  DupFields = [ "host->dest_host" ]
}
```