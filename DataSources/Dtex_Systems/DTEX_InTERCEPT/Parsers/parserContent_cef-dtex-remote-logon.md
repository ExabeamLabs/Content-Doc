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
    """\WDevice_Name=(({domain}[^\\]{1,2000})\\+)?({host}[^\\\s]{1,2000})""",
    """\WUser_Name=(({domain}[^\\\s]{1,2000})\\+)?({user}[^\\\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\|Dtex\|([^\|]{0,2000}\|){2}(SessionActivity\|)?({event_code}[^\|]{1,2000})\|""",
  ]
  DupFields = [ "host->dest_host" ]
}
```