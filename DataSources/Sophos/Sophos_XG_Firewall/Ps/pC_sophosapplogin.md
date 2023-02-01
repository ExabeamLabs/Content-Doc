#### Parser Content
```Java
{
Name = sophos-app-login
  Vendor = Sophos
  Product = Sophos XG Firewall
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """device="SFW"""", """device_name="XG330"""", """log_component="GUI""", """logged in successfully to Web Admin Console""" ]
  Fields = [
    """\Wdevice_name="({host}[^"]{1,2000})""",
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d)""",
    """\Wstatus="({outcome}[^"]{1,2000})""",
    """\Wpriority=(|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc_ip=({src_ip}[a-fA-F\d.:]{1,2000})""", 
    """\Wuser_name="(({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})|({user}[^\s@"]{1,2000}))"""",
    """\Wlog_component="({app}GUI)"""",
    """\Wmessage="({additional_info}[^"]{1,2000})(\w+=|$|")""",
    """({event_name}logged in)"""
  ]


}
```