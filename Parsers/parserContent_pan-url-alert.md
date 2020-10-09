#### Parser Content
```Java
{
Name = pan-url-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,url,""",""",malware,""" ]
  Fields = [
    """\s+({host}[^\s]+)\s+\d+,.+?,.+?,THREAT,""",
    """exabeam_host=({host}[^\s]+)""",
    """THREAT,[^,]+,\d+,({time}\d+/\d+/\d+\s+\d\d:\d\d:\d\d),({src_ip}[^,]*?),({dest_ip}[^,]*?),([^,]*?,){21}({alert_type}[^,]*),\"*({malware_url}[^",]+)?\"*,(.+?),.+?,({alert_severity}.+?),({additional_info}[^,]+),({alert_id}\d+)""",
    """,THREAT,([^,]*?,){9}(?:\w+\\)?({user}[^,]+)""",
    """,THREAT,([^,]*?,){8}(?:\w+\\)?({user}[^,]+)""",
    """\(9999\),([^,]*,){13}"?({user_agent}[^",]+)""",
    """,THREAT,([^,]*,){29}({alert_name}[^,]+),""",
    """THREAT,url,([^,]*,){26}("+)?.*?({web_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|ms|mx|))+)[\\\/\s:"]"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}
```