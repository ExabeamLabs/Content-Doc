#### Parser Content
```Java
{
Name = threatblockr-dns-response
  Vendor = ThreatBlockr
  Product = ThreatBlockr
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ threatblockr """, """ dns_resp_log """, """, query_name=""", """, answer_value=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\sthreatblockr""",
    """\ssrc=(({src_ip}[A-Fa-f\d:.]{1,2000})|({src_host}[\w\-.]{1,2000}?))(,\s\w+=|\s{0,100}$)""",
    """\sdst=(({dest_ip}[A-Fa-f\d:.]{1,2000})|({dest_host}[\w\-.]{1,2000}?))(,\s\w+=|\s{0,100}$)""",
    """\ssrc_port=({src_port}\d{1,5})""",
    """\sdst_port=({dest_port}\d{1,5})""",
    """\sproto=({protocol}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\saction=({action}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\sreason=({additional_info}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\squery_name=({query}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\squery_type=({query_type}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)""",
    """\sanswer_value=({response}[^=]{1,2000}?)(,\s\w+=|\s{0,100}$)"""
  ]
  DupFields = [ "action->outcome" ]


}
```