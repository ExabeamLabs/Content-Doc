#### Parser Content
```Java
{
Name = symantec-epp-ntp-alert-chinese
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""CIDS ???????????????""", """Intrusion ID:"""]
Fields = [
    """??????:\s*({dest_ip}[a-fA-F:\.\d]+),??????:\s*(?:0+|({dest_host}[^,]+)).*?,??????,""",
    """??????:\s*({src_ip}[a-fA-F:\.\d]+),??????:\s*(?:0+|({src_host}[^,]+)).*?,??????,""",
    """??????:\s*({src_ip}[a-fA-F:\.\d]+),??????:\s*(?:0+|({src_host}[^,]+)).*?,??????,""",
    """??????:\s*({dest_ip}[a-fA-F:\.\d]+),??????:\s*(?:0+|({dest_host}[^,]+)).*?,??????,""",
    """??????:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """??????:\s*(({user_fullname}[^,\s]+(\s+[^,\s]+)+)|({user}[^,]+)),""",
    """???:(?:\s+|\s*({domain}[^,]+)),""",
    """????????????:(?:\s+|\s*({process}({directory}(?:[^,]+)?[\\\/])?({process_name}[^\\\/,]+?))),""",
    """CIDS ?????? ID:\s*({alert_name}\d+),""",
    """Intrusion ID:\s*({alert_id}\d+),""",
    """CIDS ???????????????:\s*({alert_type}[^:,]+),""",
    """CIDS ???????????????:\s*({alert_name}[^:,]+),""",
    """CIDS ???????????????:\s*({alert_type}[^:,]+):\s*({alert_name}[^,]+)""",
    """?????? URL:(?:\s+|\s*({malware_url}[^,]+)),""",
    """CIDS ?????? ID:\s*({alert_id}\d+),""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\w{3}\s+\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]+)\s""",
    """\s*({host}[^,]+),SHA-256:""",
  ]
  DupFields = ["directory->process_directory"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "src_ip->malwareVictimHost", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp", "alert_type->malwareCategory"]
    NameTemplate = """Symantec Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```