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
    """\scat=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\srt=({time}\d{1,100})""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\ssuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\ssproc=({app}.+?)\s{1,100}(\w+=|$)""",
    """\sdvc=({host}.+?)\s{1,100}(\w+=|$)""",
    """\sdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```