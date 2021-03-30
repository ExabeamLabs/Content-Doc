#### Parser Content
```Java
{
Name = juniper-firewall-network-connection-failed
  Conditions = [ """NetScreen""", """ start_time="""", """ src zone=""", """ action=Deny""" ]
  Fields = ${JuniperParserTemplates.juniper-firewall-network-connection.Fields} [
    """\Wreason=({failure_reason}.+?)\s+(\w+=|$)""",
  ]
}
juniper-firewall-network-connection = {
  Vendor = Juniper Networks
  Product = Juniper SRX
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """\Wstart_time="({time}\d\d\d\d-\d\d-\d\d \d\d\:\d\d:\d\d)""",
    """\Wdevice_id=({host}[\w\-.]+)""",
    """\Wservice=({protocol}[^\s\/]+)""",
    """\Waction=({outcome}.+?)\s+(\w+=|$)""",
    """\Wsent=({bytes_out}\d+)""",
    """\Wrcvd=({bytes_in}\d+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc_port=({src_port}\d+)""",
    """\Wdst_port=({dest_port}\d+)""",
    """\Wsrc zone=(Null|({src_zone}.+?))\s+dst zone=""",
    """\Wdst zone=(Null|({dest_zone}.+?))\s+action=""",
    """\Wsrc-xlated ip=({src_translated_ip}[A-Fa-f:\d.]+)""",
    """\Wdst-xlated ip=({dest_translated_ip}[A-Fa-f:\d.]+)""",
    """\Wsession_id=({session_id}.+?)\s+(\w+=|$)""",
  ]

```