#### Parser Content
```Java
{
Name = cef-asa-svc-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|CISCO|ASA|""", """|722051|"""]
  Fields = [
	"""\srt=({time}\d+)""",
	"""\sdvc=({host}[^\s]+)""",
	"""\sdvchost=({host}[^\s]+)""",
    """\sdvchost=({dest_host}[^\s]+)""",
    """\sduser=({user_fullname}(\w+\s+)+\w+)\s+(\w+=|$)""",
    """\sduser=({user}[^\s@]+)\s+(\w+=|$)""",
    """\sduser=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
    """\sdhost=(?: |<?({src_ip}[a-fA-F\d.:]+)>?)\s+\w+=""",
    """\ssrc=({src_translated_ip}[a-fA-F\d.:]+)""",
    """\sdst=({src_ip}[a-fA-F\d.:]+)""",
	"""\sc6a3=(?: |0:0:0:0:0:0:0:0|({src_translated_ip}.+?))\s+\w+="""
  ]
}
```