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
    """\s{1,100}({host}[^\s]{1,2000})\s{1,100}\d{1,100},.+?,.+?,THREAT,""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,[^,]{1,2000},\d{1,100},({time}\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d\d:\d\d:\d\d),({src_ip}[^,]{0,2000}?),({dest_ip}[^,]{0,2000}?),([^,]{0,2000}?,){21}({alert_type}[^,]{0,2000}),\"{0,20}({malware_url}[^",]{1,2000})?\"{0,20},([^,]{1,2000}?),[^,]{1,2000}?,({alert_severity}[^,]{1,2000}?),({additional_info}[^,]{1,2000}),({alert_id}\d{1,100})""",
    """,THREAT,([^,]{0,2000}?,){9}(?:\w+\\)?({user}[^,]{1,2000})""",
    """,THREAT,([^,]{0,2000}?,){8}(?:\w+\\)?({user}[^,]{1,2000})""",
    """\(9999\),([^,]{0,2000},){13}"?({user_agent}[^",]{1,2000})""",
    """,THREAT,([^,]{0,2000},){29}({alert_name}[^,]{1,2000}),""",
    """THREAT,url,([^,]{0,2000},){26}("{1,20})?.*?({web_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|ms|mx|))+)[\\\/\s:"]""",
    """,(any|({category}[^,]{1,2000}?)),Informational,client to server,"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}
```