#### Parser Content
```Java
{
Name = msnetwork-nac-logon-2
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy,HH:mm:ss"
  Conditions = [ ""","IAS",""", """,13,"""]
  Fields = [
    """"({host}[^\,]{1,2000})","IAS",({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d,\d{0,100}
```