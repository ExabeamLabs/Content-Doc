#### Parser Content
```Java
{
Name = cef-carbonblack-app-login
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Protection|""", "|Console user login|" ]
  Fields = [
    """\srt=({time}\d+)""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s+[\w-]+=|\s*$)""",
    """(\||\s)dvc=(|({host_ip}.+?))\s+(\w+=|$)""",
    """(\||\s)duser=(|({domain}[^\s\\]+)\\+)?({user}.+?)(\s+\w+=|\s*$)""",
    """msg=User\s'({user_email}[^@]+@({email_domain}[^']+))""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s*$)""",
    """(\||\s)msg=.+from\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```