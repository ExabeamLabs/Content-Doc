#### Parser Content
```Java
{
Name = microsoft-nps-nac-logon
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|NPS|""", """|Access-Accept|""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdntdom=({domain}[^\s]{1,2000})""",
    """\sdestinationZoneURI=({network}.+?)\s{1,100}\w+="""
  ]


}
```