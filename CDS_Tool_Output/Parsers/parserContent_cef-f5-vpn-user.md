#### Parser Content
```Java
{
Name = cef-f5-vpn-user
  Vendor = F5
  Product = Access Policy Manager
  Lms = ArcSight
  DataType = "vpn-user"
  TimeFormat = "epoch"
  Conditions = [ """|F5|APM|""", """Username|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sduser=({user}.+?)(?:\s+[\w.]+=|\s*$)""",
    """\scs4=({session_id}.+?)(?:\s+[\w.]+=|\s*$)""",
    """\sdvc=({host}[a-fA-F\d.:]+)""",
    """\sdvchost=({host}.+?)(?:\s+[\w.]+=|\s*$)"""
  ]
}

{
  Name = f5-vpn-login-failed
  Vendor = F5
  Product = Big-IP
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """01490106:4""" ]
  Fields = [
    """@timestamp"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """exabeam_host=({host}[\w\.\-]+)""",
    """\sprincipal name:\s*({user}[^@\.]+)(@({domain}.+?))?\.\s+({failure_reason}[^\.]+)""",
  ]
}
```