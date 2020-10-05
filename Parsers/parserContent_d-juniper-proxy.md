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
```