#### Parser Content
```Java
{
Name = msnetwork-nac-logon-4
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy,HH:mm:ss"
  Conditions = [ ""","RAS",""", """win_nps""" ]
  Fields = [
    """"({host}[^,"]+)","RAS",({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d,\d*,("({domain}[^\\]+)\\+({user}[^"]+)"|[^,]*),("({src_host}[^,"\\\/]+)[^"]*?({user_fullname}[^"\\\/]+)"|[,]*),([^,]*,){8}("({src_ip}[a-fA-F\d.:]+)"|[^,]*),""",
    """({dest_host}[\w.\-]+)\s+\d\d\/\d\d\/\d\d\d\d\s"""
  ]
}
```