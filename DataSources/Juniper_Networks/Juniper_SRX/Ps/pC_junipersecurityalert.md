#### Parser Content
```Java
{
Name = juniper-security-alert
    Vendor = Juniper Networks
    Product = Juniper SRX
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """RT_UTM - AV_VIRUS_DETECTED_MT""", """name="""", """filename="""", """url="""" ]
    Fields = [
      """\sdestination-address="({dest_ip}[^"]{0,2000})""",
      """\sdestination-port="({dest_port}[^"]{0,2000})""",
      """\s({alert_type}RT_UTM - [^\s]{0,2000})\s\[""",
      """\s({host}[^\s]{0,2000})\sRT_UTM""",
      """\ssource-address="({src_ip}[^"]{0,2000})"""
      """\ssource-port="({src_port}[^"]{0,2000})""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(?:z|Z)?""",
      """\susername="(?!N\/A)({user}[^"]{1,2000})"""",
      """\ssource-zone-name="({src_network_zone}[^"]{0,2000})""",
      """\sfilename="({malware_url}[^"]{1,2000})""",
      """\surl="({additional_info}[^"]{1,2000})""",
      """\sname="({alert_name}[^"]{1,2000})""",
    ]
}
```