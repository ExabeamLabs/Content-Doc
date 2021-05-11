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
    """({host}[\w\-.]+)\s{1,100}SFIMS:""",
    """\WProtocol:\s{0,100}({protocol}[^,]+)\s{0,100}(,|$)""",
    """\WSrcIP:\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\WDstIP:\s{0,100}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\WSrcPort:\s{0,100}({src_port}\d{1,100})""",
    """\WDstPort:\s{0,100}({dest_port}\d{1,100})""",
    """\WIngressZone:\s{0,100}({ingress_zone}[^,]+)\s{0,100}(,|$)""",
    """\WEgressZone:\s{0,100}({egress_zone}[^,]+)\s{0,100}(,|$)""",
    """\WDE:\s{0,100}({engine_name}[^,]+)\s{0,100}(,|$)""",
    """\WRevision:\s{0,100}({revision}[^,]+)\s{0,100}(,|$)""",
    """\WPolicy:\s{0,100}({policy}[^,]+)\s{0,100}(,|$)"""
    """\WAccessControlRuleAction:\s{0,100}({outcome}[^,]+)""",
    """\WUserName:\s{0,100}({user}[^,]+)""",
    """InitiatorBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """\WResponderBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """NAPPolicy:\s{0,100}({nap_policy}[^,]+)""",
    """\sDNSQuery:\s{0,100}({query}[^,]+)""",
    """\WDNSResponseType:\s{0,100}({response_type}[^,]+)""",
    """\sDNSRecordType:\s{0,100}({query_type}[^,]+)""",
    """URLCategory:\s{0,100}({category}[^,]+)""",
    """\WURLReputation:\s{0,100}({reputation}[^,]+?)(,|\s{0,100}$)""",
  ]
}
```