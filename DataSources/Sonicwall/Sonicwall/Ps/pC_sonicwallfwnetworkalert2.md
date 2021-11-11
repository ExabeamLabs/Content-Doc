#### Parser Content
```Java
{
Name = sonicwall-fw-network-alert-2
  Product = Sonicwall
  DataType = "network-alert"
  Conditions = [ """ m=""", """id=""", """ fw=""", """ c=""" ,""" msg="""", """ pri=2 """, """ src=""", """ dst="""]
}
sonicwall-firewall = {
  Vendor = Sonicwall
  Product = Sonicwall
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """time="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\suser="\s{0,100}(({user_email}[^@"]{1,2000}@[^\\\s"]{1,2000})|({user}[^\\\s"]{1,2000}))""",
    """usr="\s{0,100}(({user_email}[^@"]{1,2000}@[^\\\s"]{1,2000})|({user}[^\\\s"]{1,2000}))""", 
    """\smsg="({additional_info}[^"]{1,2000}?)\s{0,100}"""", 
    """\sc=({category_id}\d{1,100})""",
    """\sm=({message_id}\d{1,100})""",
    """\sipscat="({category}[^"]{1,2000})""",  
    """\sipspri=({alert_severity}\d{1,100})""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({src_port}\d{1,100}))?(:({src_interface}[^\s:]{1,2000}))?(:[^\s:]{1,2000})?""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?(:({dest_interface}[^\s:]{1,2000}))?(:[^\s:]{1,2000})?""",
    """\ssrcMac=({src_mac}[a-fA-F\d.:]{1,2000})""",
    """\sdstMac=({dest_mac}[a-fA-F\d.:]{1,2000})""",
    """\sproto=({protocol}[^\s\/\d"]{1,2000})""",
    """\srcvd=({bytes_in}\d{1,100})""",
    """\ssent=({bytes_out}\d{1,100})""",
    """\sfw=({firewall}[a-fA-F\d.:]{1,2000})""",
    """\smsg="({alert_name}[^:"-]{1,2000}?)\s{0,100}(:|"|-)""",
    """\smsg="({alert_name}Possible \w+ Flood)""",
    """\spri=({alert_severity}\d{1,100})""",
    """\srule="({rule}[^"]{1,2000})""",
    """\sfw_action="(NA|({action}[^"]{1,2000}))"""
  ]
  DupFields = [ "message_id->alert_type" ]}
```