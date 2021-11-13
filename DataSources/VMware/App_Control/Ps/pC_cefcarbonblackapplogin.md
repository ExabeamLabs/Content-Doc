#### Parser Content
```Java
{
Name = cef-carbonblack-app-login
  Vendor = VMware
  Product = App Control
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Protection|""", "|Console user login|" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """(\||\s)dst=(|({dest_ip}.+?))(\s{1,100}[\w-]{1,2000}=|\s{0,100}$)""",
    """(\||\s)dvc=(|({host_ip}.+?))\s{1,100}(\w+=|$)""",
    """(\||\s)duser=(|({domain}[^\s\\]{1,2000})\\+)?({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """msg=User\s'({user_email}[^@]{1,2000}@({email_domain}[^']{1,2000}))""",
    """(\||\s)dvchost=(|({host}.+?))(\s\w+=|\s{0,100}$)""",
    """(\||\s)msg=.+from\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]


}
```