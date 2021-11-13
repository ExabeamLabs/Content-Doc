#### Parser Content
```Java
{
Name = symantec-security-alert-2
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ SymantecServer: """, """Event Description:""", """Web Attack:""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """Begin:\s{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s({host}[\w.\-]{1,2000})\s{1,100}SymantecServer:\s{0,100}({src_host}[^,]{1,2000})""",
    """\s{0,100}\w{1,2000

}
```