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
    """\Wstart=({time}\d{1,100})""",
    """\WDevice_Name=(({domain}[^\\]{1,2000})\\+)?({host}[^\\\s]{1,2000})""",
    """\WUser_Name=(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})\s""",
    """\|Dtex\|([^\|]{0,2000}\|){2}(SessionActivity\|)?({event_code}[^\|]{1,2000})\|""",
  ]
  DupFields = [ "host->dest_host" ]
}
```