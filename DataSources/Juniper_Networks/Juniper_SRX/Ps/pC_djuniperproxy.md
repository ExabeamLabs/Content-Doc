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
      """\sdestination-address="({dest_ip}[^"]{0,2000})""",
      """\sdestination-port="({dest_port}[^"]{0,2000})""",
      """\s({host}[^\s]{0,2000})\sRT_UTM""",
      """\ssource-address="({src_ip}[^"]{0,2000})""",
      """\ssource-port="({src_port}[^"]{0,2000})""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(?:z|Z)?""",
      """\susername="(?!N\/A)({user}[^"]{1,2000})"""",
      """\ssource-zone-name="({src_network_zone}[^"]{0,2000})""",
      """\sprofile="({profile}[^"]{1,2000})""",
      """\sname="({alert_name}[^"]{1,2000})""",
      """\scategory="({category}[^"]{1,2000})""",
      """({action}PERMITTED|BLOCKED)""",
      """\sreason="({reason}[^"]{1,2000})""",
      """\surl="({web_domain}[^"]{1,2000})""",
      """\sobj="({uri_path}\/[^\s\?]{1,2000})?({uri_query}\?[^\s]{1,2000})?""""
 ]
  DupFields = [ "action->outcome" ]


}
```