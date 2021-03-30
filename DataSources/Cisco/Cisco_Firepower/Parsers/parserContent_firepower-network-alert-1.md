#### Parser Content
```Java
{
Name = firepower-network-alert-1
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [""" SFIMS: """, """ Sinkhole: """, """ OriginalClientIP: """]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s+SFIMS:""",
    """\WProtocol:\s*({protocol}[^,]+)\s*(,|$)""",
    """\WSrcIP:\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\WDstIP:\s*({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\WSrcPort:\s*({src_port}\d+)""",
    """\WDstPort:\s*({dest_port}\d+)""",
    """\WIngressZone:\s*({ingress_zone}[^,]+)\s*(,|$)""",
    """\WEgressZone:\s*({egress_zone}[^,]+)\s*(,|$)""",
    """\WDE:\s*({engine_name}[^,]+)\s*(,|$)""",
    """\WRevision:\s*({revision}[^,]+)\s*(,|$)""",
    """\WPolicy:\s*({policy}[^,]+)\s*(,|$)"""
    """\WAccessControlRuleAction:\s*({outcome}[^,]+)""",
    """\WUserName:\s*({user}[^,]+)""",
    """InitiatorBytes:\s*({bytes_in}\d+)""",
    """\WResponderBytes:\s*({bytes_out}\d+)""",
    """NAPPolicy:\s*({nap_policy}[^,]+)""",
    """\sDNSQuery:\s*({query}[^,]+)""",
    """\WDNSResponseType:\s*({response_type}[^,]+)""",
    """\sDNSRecordType:\s*({query_type}[^,]+)""",
    """URLCategory:\s*({category}[^,]+)""",
    """\WURLReputation:\s*({reputation}[^,]+?)(,|\s*$)""",
  ]
}
```