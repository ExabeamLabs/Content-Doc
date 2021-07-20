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
	"""\sdvc=({host}[^\s]{1,2000})""",
	"""\sdvchost=({host}[^\s]{1,2000})""",
    """\sdvchost=({dest_host}[^\s]{1,2000})""",
    """\sduser=({user_fullname}(\w+\s{1,100})+\w+)\s{1,100}(\w+=|$)""",
    """\sduser=({user}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\sduser=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\sdhost=(?: |<?({src_ip}[a-fA-F\d.:]{1,2000})|({src_host}[^\s]{1,2000})>?)\s{1,100}\w+=""",
    """\ssrc=({src_translated_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdst=({dst_ip}[a-fA-F\d.:]{1,2000})""",
	"""\sc6a3=(?: |0:0:0:0:0:0:0:0|({src_translated_ip}.+?))\s{1,100}\w+="""
  ]
  DupFields = ["user->account"]
}
```