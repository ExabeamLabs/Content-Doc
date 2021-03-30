#### Parser Content
```Java
{
Name = sonicwall-network-alert-1
  Product = Sonicwall
  DataType = "network-alert"
  Conditions = [ """id=firewall""", """msg="Invalid SNMP""", """c=0""" ]
  Fields = ${SonicwallParserTemplates.sonicwall-firewall.Fields}[
    """\snote="({additional_info}[^"]+)""",
  ]
}
sonicwall-firewall = {
  Vendor = Sonicwall
  Product = Sonicwall
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\stime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\smsg="({event_name}[^"]+)""",
    """\ssn=({serial_number}.+?)(\s+\w+=|\s*$)""",
    """\sc=({category_id}\d+)""",
    """\sm=({message_id}\d+)""",
    """\smsg="({alert_type}[^:"]+?)\s*:\s*({alert_name}[^"]+)""",
    """\ssid=({signature_id}\d+)""",
    """\sipscat="({ips_category}[^"]+)""",
    """\sipspri=({alert_severity}\d+)""",
    """\sn=({message_count}\d+)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d+)(:({src_interface}\S+))?""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d+)(:({dest_interface}[^\s:]+))?(:({dest_host}[^\s:]+))?""",
    """\ssrcMac=({src_mac}[a-fA-F\d.:]+)""",
    """\sdstMac=({dest_mac}[a-fA-F\d.:]+)""",
    """\sproto=({protocol}\S+)""",
    """\srcvd=({bytes_in}\d+)""",
    """\ssent=({bytes_out}\d+)""",
    """\sfw=({firewall}[a-fA-F\d.:]+)"""
  ]

```