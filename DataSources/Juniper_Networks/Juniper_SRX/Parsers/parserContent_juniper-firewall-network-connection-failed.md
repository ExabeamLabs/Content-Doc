#### Parser Content
```Java
{
Name = juniper-firewall-network-connection-failed
  Conditions = [ """NetScreen""", """ start_time="""", """ src zone=""", """ action=Deny""" ]
  Fields = ${JuniperParserTemplates.juniper-firewall-network-connection.Fields} [
    """\Wreason=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
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
    """\Wdevice_id=({host}[\w\-.]{1,2000})""",
    """\Wservice=({protocol}[^\s\/]{1,2000})""",
    """\Waction=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wsent=({bytes_out}\d{1,100})""",
    """\Wrcvd=({bytes_in}\d{1,100})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc_port=({src_port}\d{1,100})""",
    """\Wdst_port=({dest_port}\d{1,100})""",
    """\Wsrc zone=(Null|({src_zone}.+?))\s{1,100}dst zone=""",
    """\Wdst zone=(Null|({dest_zone}.+?))\s{1,100}action=""",
    """\Wsrc-xlated ip=({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst-xlated ip=({dest_translated_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsession_id=({session_id}.+?)\s{1,100}(\w+=|$)""",
  ]

```