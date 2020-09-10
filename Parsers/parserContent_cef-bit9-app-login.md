#### Parser Content
```Java
{
Name = cef-bit9-app-login
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """|Bit9|Security Platform|""", "|Console user login|" ]
  Fields = [
    """(exabeam_\w+=|^)({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s+[\w-]+=|\s*$)""",
    """(\||\s)duser=(|({domain}[^\s\\]+)\\+)?({user}.+?)(\s+\w+=|\s*$)""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s*$)""",
    """(\||\s)msg=.+from\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```