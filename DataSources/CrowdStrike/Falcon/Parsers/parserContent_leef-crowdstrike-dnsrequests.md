#### Parser Content
```Java
{
Name = leef-crowdstrike-dnsrequests
  Conditions = [ """0|CrowdStrike|FalconHost|""", """cat=DnsRequests""" ]
  Fields = ${CrowdStrikeParserTemplates.leef-crowdstrike-alert-t.Fields} [
    """CrowdStrike\|([^|]+\|){2}({alert_type}[^|]+)""",
    """\WdnsRequestDomain=({alert_name}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WdnsRequestDomain=({malware_url}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)""",
    """\WrequestType=({query_type}.+?)(\t|\s+\w+=|\s*\||\s*$|\s*"+\s*$)"""
  ]
}
```