#### Parser Content
```Java
{
Name = msnetwork-nac-logon-3
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy,HH:mm:ss"
  Conditions = [ ""","IAS",""", """win_nps""" ]
  Fields = [
    """"({host}[^,"]+)","IAS",({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d,\d*,("host\/({src_host}[^,"]+?)"|[,]*),("({domain}[^\\]+)\\+({user}[^"]+)"|[^,]*),([^,]*,){8}("({src_ip}[a-fA-F\d.:]+)"|[^,]*),""",
    """({dest_host}[\w.\-]+)\s+\d\d\/\d\d\/\d\d\d\d\s"""
  ]
}
```