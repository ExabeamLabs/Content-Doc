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
    """({host}[\w\-.]{1,2000})\s{1,100}SFIMS:""",
    """\WProtocol:\s{0,100}({protocol}[^,]{1,2000})\s{0,100}(,|$)""",
    """\WSrcIP:\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\WDstIP:\s{0,100}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\WSrcPort:\s{0,100}({src_port}\d{1,100})""",
    """\WDstPort:\s{0,100}({dest_port}\d{1,100})""",
    """\WIngressZone:\s{0,100}({ingress_zone}[^,]{1,2000})\s{0,100}(,|$)""",
    """\WEgressZone:\s{0,100}({egress_zone}[^,]{1,2000})\s{0,100}(,|$)""",
    """\WDE:\s{0,100}({engine_name}[^,]{1,2000})\s{0,100}(,|$)""",
    """\WRevision:\s{0,100}({revision}[^,]{1,2000})\s{0,100}(,|$)""",
    """\WPolicy:\s{0,100}({policy}[^,]{1,2000})\s{0,100}(,|$)"""
    """\WAccessControlRuleAction:\s{0,100}({outcome}[^,]{1,2000})""",
    """\WUserName:\s{0,100}({user}[^,]{1,2000})""",
    """InitiatorBytes:\s{0,100}({bytes_in}\d{1,100})""",
    """\WResponderBytes:\s{0,100}({bytes_out}\d{1,100})""",
    """NAPPolicy:\s{0,100}({nap_policy}[^,]{1,2000})""",
    """\sDNSQuery:\s{0,100}({query}[^,]{1,2000})""",
    """\WDNSResponseType:\s{0,100}({response_type}[^,]{1,2000})""",
    """\sDNSRecordType:\s{0,100}({query_type}[^,]{1,2000})""",
    """URLCategory:\s{0,100}({category}[^,]{1,2000})""",
    """\WURLReputation:\s{0,100}({reputation}[^,]{1,2000}?)(,|\s{0,100}$)""",
  ]
}
```