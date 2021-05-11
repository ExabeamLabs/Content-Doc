#### Parser Content
```Java
{
Name = cef-dtex-remote-logon
  Vendor = Dtex Systems
  Product = DTEX InTERCEPT
  Lms = ArcSight
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Dtex|""", """|SessionActivity|SessionRemoteConnected|""" ]
  Fields = [
    """\Wstart=({time}\d{1,100})""",
    """\WDevice_Name=(({domain}[^\\]+)\\+)?({host}[^\\\s]+)""",
    """\WUser_Name=(({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)\s{1,100}(\w+=|$)""",
    """\|Dtex\|([^\|]*\|){2}(SessionActivity\|)?({event_code}[^\|]+)\|""",
  ]
  DupFields = [ "host->dest_host" ]
}
```