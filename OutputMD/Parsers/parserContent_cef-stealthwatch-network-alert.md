#### Parser Content
```Java
{
Name = cef-stealthwatch-network-alert
  Vendor = Cisco
  Product = Cisco StealthWatch (Lancope)
  Lms = Direct
  DataType = "network-alert"
  TimeFormat =  "epoch"
  Conditions = [ """CEF:""", """|Lancope|StealthWatch|""" ]
  Fields = [
    """\sahost=({host}.+?)\s+\w+="""
    """\sdvchost=({dest_host}.+?)\s+\w+="""
    """\sshost=({src_host}.+?)\s+\w+="""
    """CEF:\s*\d+\|Lancope\|StealthWatch\|.*?\|.*?\|({alert_name}[^\|]+)\|({alert_severity}[^\|]+)\|"""
    """\srt=({time}\d+)""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]+))""",
    """\Wdst=(0.0.0.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\WdstPort=({dest_port}\d+)""",
    """\smsg=({additional_info}.+?)\s+\w+="""
    """\scatdt=({alert_type}.+?)\s+\w+="""
    """\sexternalId=({alert_id}.+?)\s+\w+="""
  ]
}
```