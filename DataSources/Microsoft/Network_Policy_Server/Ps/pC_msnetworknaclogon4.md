#### Parser Content
```Java
{
Name = msnetwork-nac-logon-4
  Vendor = Microsoft
  Product = Network Policy Server 
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy,HH:mm:ss"
  Conditions = [ ""","RAS",""", """win_nps""" ]
  Fields = [
    """"({host}[^,"]{1,2000})","RAS",({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d,\d{0,100},("({domain}[^\\]{1,2000})\\+({user}[^"]{1,2000})"|[^,]{0,2000}),("({src_host}[^,"\\\/]{1,2000})[^"]{0,2000}?({user_fullname}[^"\\\/]{1,2000})"|[,]{0,2000}),([^,]{0,2000},){8}("({src_ip}[a-fA-F\d.:]{1,2000})"|[^,]{0,2000}),""",
    """({dest_host}[\w.\-]{1,2000})\s{1,100}\d\d\/\d\d\/\d\d\d\d\s"""
  ]
}
```