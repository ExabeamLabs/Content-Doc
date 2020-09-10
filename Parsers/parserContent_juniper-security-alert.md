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
      """\sdestination-address="({dest_ip}[^"]*)""",
      """\sdestination-port="({dest_port}[^"]*)""",
      """\s({alert_type}RT_UTM - [^\s]*)\s\[""",
      """\s({host}[^\s]*)\sRT_UTM""",
      """\ssource-address="({src_ip}[^"]*)"""
      """\ssource-port="({src_port}[^"]*)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(?:z|Z)?""",
      """\susername="(?!N\/A)({user}[^"]+)"""",
      """\ssource-zone-name="({src_network_zone}[^"]*)""",
      """\sfilename="({malware_url}[^"]+)""",
      """\surl="({additional_info}[^"]+)""",
      """\sname="({alert_name}[^"]+)""",
    ]
}
```