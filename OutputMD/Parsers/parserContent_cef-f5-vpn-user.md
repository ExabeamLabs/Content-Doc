#### Parser Content
```Java
{
Name = cef-f5-vpn-user
  Vendor = F5 Networks
  Product = F5 BIG-IP Access Policy Manager (APM)
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