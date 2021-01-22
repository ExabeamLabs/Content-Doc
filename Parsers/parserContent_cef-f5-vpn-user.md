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
```