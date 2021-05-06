#### Parser Content
```Java
{
Name = sonicwall-fw-web-activity
  Product = Sonicwall
  DataType = "web-activity"
  Conditions = [ """ m=97 """, """id=""", """ fw=""", """ c=1024 """, """ pri=""", """ src=""", """ dst="""]
  Fields = ${SonicwallParserTemplates.sonicwall-firewall.Fields} [
    """Category="({category}[^"]+)""",
    """dstname=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({web_domain}[^"\/\s]+))""",
    """dstname=(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^=]*?({top_domain}[^\s."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""" 
  ]
}
sonicwall-firewall = {
  Vendor = Sonicwall
  Product = Sonicwall
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """time="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\suser="\s*(({user_email}[^@"]+@[^\\\s"]+)|({user}[^\\\s"]+))""",
    """usr="\s*(({user_email}[^@"]+@[^\\\s"]+)|({user}[^\\\s"]+))""", 
    """\smsg="({additional_info}[^"]+?)\s*"""", 
    """\sc=({category_id}\d+)""",
    """\sm=({message_id}\d+)""",
    """\sipscat="({category}[^"]+)""",  
    """\sipspri=({alert_severity}\d+)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({src_port}\d+))?(:({src_interface}[^\s:]+))?(:[^\s:]+)?""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d+))?(:({dest_interface}[^\s:]+))?(:[^\s:]+)?""",
    """\ssrcMac=({src_mac}[a-fA-F\d.:]+)""",
    """\sdstMac=({dest_mac}[a-fA-F\d.:]+)""",
    """\sproto=({protocol}[^\s\/\d"]+)""",
    """\srcvd=({bytes_in}\d+)""",
    """\ssent=({bytes_out}\d+)""",
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
    """\smsg="({alert_name}[^:"-]+?)\s*(:|"|-)""",
    """\smsg="({alert_name}Possible \w+ Flood)""",
    """\spri=({alert_severity}\d+)""",
    """\srule="({rule}[^"]+)""",
    """\sfw_action="(NA|({action}[^"]+))"""
  ]

```