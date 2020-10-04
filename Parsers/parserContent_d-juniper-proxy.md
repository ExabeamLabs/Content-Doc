#### Parser Content
```Java
{
Name = d-juniper-proxy
  Vendor = Juniper Networks
  Product = Juniper SRX
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """RT_UTM - WEBFILTER_URL_""", """ url="""", """ category=""""]
  Fields = [
      """\sdestination-address="({dest_ip}[^"]*)""",
      """\sdestination-port="({dest_port}[^"]*)""",
      """\s({host}[^\s]*)\sRT_UTM""",
      """\ssource-address="({src_ip}[^"]*)""",
      """\ssource-port="({src_port}[^"]*)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(?:z|Z)?""",
      """\susername="(?!N\/A)({user}[^"]+)"""",
      """\ssource-zone-name="({src_network_zone}[^"]*)""",
      """\sprofile="({profile}[^"]+)""",
      """\sname="({alert_name}[^"]+)""",
      """\scategory="({category}[^"]+)""",
      """({action}PERMITTED|BLOCKED)""",
      """\sreason="({reason}[^"]+)""",
      """\surl="({web_domain}[^"]+)""",
      """\sobj="({uri_path}\/[^\s\?]+)?({uri_query}\?[^\s]+)?""""
      """\surl=(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:"]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+("|\s|\/|:|$))[^\s\/:"]+)""", 
 ]
  DupFields = [ "action->outcome" ]
}
{
  Name = cef-juniper-vpn-close
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Juniper|""", """|Closed connection|""", """ bytes read """, """ bytes written """ ]
  Fields = [
	"""\Wrt=({time}\d+)""",
	"""\Wdvchost=({host}[\w\-.]+)""",
	"""\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
	"""\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
	"""\Wsuser=(System|({user}[^\s]+))""",
	"""\Wshost=({src_host}[\w\-.]+)""",
    """\Wafter\s+({session_duration}\d+)\s+seconds""",
    """\Wwith\s+({bytes_in}\d+)\s+bytes read""",
    """\Wand\s+({bytes_out}\d+)\s+bytes written"""
    """\Wmsg=({additional_info}.+?)\s+end=""",
    """Closed connection to=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```