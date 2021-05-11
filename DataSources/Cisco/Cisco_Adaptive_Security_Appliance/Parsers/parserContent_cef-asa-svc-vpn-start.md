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
	"""\srt=({time}\d{1,100})""",
	"""\sdvc=({host}[^\s]+)""",
	"""\sdvchost=({host}[^\s]+)""",
    """\sdvchost=({dest_host}[^\s]+)""",
    """\sduser=({user_fullname}(\w+\s{1,100})+\w+)\s{1,100}(\w+=|$)""",
    """\sduser=({user}[^\s@]+)\s{1,100}(\w+=|$)""",
    """\sduser=({user_email}[^\s@]+@[^\s@]+)\s{1,100}(\w+=|$)""",
    """\sdhost=(?: |<?({src_ip}[a-fA-F\d.:]+)|({src_host}[^\s]+)>?)\s{1,100}\w+=""",
    """\ssrc=({src_translated_ip}[a-fA-F\d.:]+)""",
    """\sdst=({dst_ip}[a-fA-F\d.:]+)""",
	"""\sc6a3=(?: |0:0:0:0:0:0:0:0|({src_translated_ip}.+?))\s{1,100}\w+="""
  ]
  DupFields = ["user->account"]
}
```