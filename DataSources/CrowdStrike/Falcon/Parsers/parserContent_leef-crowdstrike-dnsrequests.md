#### Parser Content
```Java
{
Name = leef-crowdstrike-dnsrequests
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=DnsRequests""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_name}[^|]+)""",
    """\WdnsRequestDomain=({query}[^\s|"]+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WrequestType=({query_type}[^="|]+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)"""
  ]
   DupFields = ["query->malware_url", "category->alert_type"]
}
```