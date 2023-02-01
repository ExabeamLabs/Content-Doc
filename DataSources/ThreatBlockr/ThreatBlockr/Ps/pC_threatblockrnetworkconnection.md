#### Parser Content
```Java
{
Name = threatblockr-network-connection
  Vendor = ThreatBlockr
  Product = ThreatBlockr
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ threatblockr """, """ packet_log """, """, as_name=""", """, as_num=""", """ action=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\sthreatblockr""",
    """\ssrc=(({src_ip}[A-Fa-f\d:.]{1,2000})|({src_host}[\w\-.]{1,2000}?))(,\s\w+=|\s{0,100}$)""",
    """\sdst=(({dest_ip}[A-Fa-f\d:.]{1,2000})|({dest_host}[\w\-.]{1,2000}?))(,\s\w+=|\s{0,100}$)""",
    """\ssrc_port=({src_port}\d{1,5})""",
    """\sdst_port=({dest_port}\d{1,5})""",
    """\sdirection=({direction}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\sproto=({protocol}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\saction=({action}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\sreason=({additional_info}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\sgroup="({group_name}[^"]{1,2000}?)"(,\s\w+=|\s{0,100}$)""",
    """\scountry="({country}[^"]{1,2000}?)"(,\s\w+=|\s{0,100}$)""",
    """\s(al|dl)_active="({rule}[^"]{1,2000}?)"(,\s\w+=|\s{0,100}$)"""
  ]
  DupFields = [ "action->outcome" ]


}
```