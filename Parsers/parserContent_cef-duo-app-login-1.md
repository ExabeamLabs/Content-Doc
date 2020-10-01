#### Parser Content
```Java
{
Name = cef-duo-app-login-1
  Vendor = Cisco
  Product = Duo Access Security
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Duo Security|Two-Factor|""", """|SUCCESS|""" ]
  Fields = [
    """\|Duo Security\|({login_type}[^\|]+)\|[^\|]*\|({outcome}[^\|]+)\|""",
    """\scat=({additional_info}.+?)\s+(\w+=|$)""",
    """\srt=({time}\d+)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\ssuser=({user}.+?)\s+(\w+=|$)""",
    """\ssproc=({app}.+?)\s+(\w+=|$)""",
    """\sdvc=({host}.+?)\s+(\w+=|$)""",
    """\sdvchost=({host}.+?)\s+(\w+=|$)""",
  ]
}
```