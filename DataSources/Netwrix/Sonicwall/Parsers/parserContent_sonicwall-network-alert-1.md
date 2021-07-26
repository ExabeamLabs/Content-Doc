#### Parser Content
```Java
{
Name = sonicwall-network-alert-1
  Product = Sonicwall
  DataType = "network-alert"
  Conditions = [ """id=firewall""", """msg="Invalid SNMP""", """c=0""" ]
  Fields = ${SonicwallParserTemplates.sonicwall-firewall.Fields}[
    """\snote="({additional_info}[^"]{1,2000})""",
  ]
}
sonicwall-firewall = {
  Vendor = Sonicwall
  Product = Sonicwall
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\stime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\smsg="({event_name}[^"]{1,2000})""",
    """\ssn=({serial_number}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sc=({category_id}\d{1,100})""",
    """\sm=({message_id}\d{1,100})""",
    """\smsg="({alert_type}[^:"]{1,2000}?)\s{0,100}:\s{0,100}({alert_name}[^"]{1,2000})""",
    """\ssid=({signature_id}\d{1,100})""",
    """\sipscat="({ips_category}[^"]{1,2000})""",
    """\sipspri=({alert_severity}\d{1,100})""",
    """\sn=({message_count}\d{1,100})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100})(:({src_interface}\S+))?""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100})(:({dest_interface}[^\s:]{1,2000}))?(:({dest_host}[^\s:]{1,2000}))?""",
    """\ssrcMac=({src_mac}[a-fA-F\d.:]{1,2000})""",
    """\sdstMac=({dest_mac}[a-fA-F\d.:]{1,2000})""",
    """\sproto=({protocol}\S+)""",
    """\srcvd=({bytes_in}\d{1,100})""",
    """\ssent=({bytes_out}\d{1,100})""",
    """\sfw=({firewall}[a-fA-F\d.:]{1,2000})"""
  ]

```