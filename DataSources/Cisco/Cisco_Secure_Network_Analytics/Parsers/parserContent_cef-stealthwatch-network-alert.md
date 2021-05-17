#### Parser Content
```Java
{
Name = cef-stealthwatch-network-alert
  Vendor = Cisco
  Product = Cisco Secure Network Analytics
  Lms = Direct
  DataType = "network-alert"
  TimeFormat =  "epoch"
  Conditions = [ """CEF:""", """|Lancope|StealthWatch|""" ]
  Fields = [
    """\sahost=({host}.+?)\s{1,100}\w+="""
    """\sdvchost=({dest_host}.+?)\s{1,100}\w+="""
    """\sshost=({src_host}.+?)\s{1,100}\w+="""
    """CEF:\s{0,100}\d{1,100}\|Lancope\|StealthWatch\|.*?\|.*?\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|"""
    """\srt=({time}\d{1,100})""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wdst=(0.0.0.0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\smsg=({additional_info}.+?)\s{1,100}\w+="""
    """\scatdt=({alert_type}.+?)\s{1,100}\w+="""
    """\sexternalId=({alert_id}.+?)\s{1,100}\w+="""
  ]
}
```