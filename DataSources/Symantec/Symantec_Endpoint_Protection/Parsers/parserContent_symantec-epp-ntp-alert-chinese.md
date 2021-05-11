#### Parser Content
```Java
{
Name = symantec-epp-ntp-alert-chinese
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""CIDS 特征字符串""", """Intrusion ID:"""]
Fields = [
    """本地:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),本地:\s{0,100}(?:0+|({dest_host}[^,]+)).*?,入站,""",
    """远程:\s{0,100}({src_ip}[a-fA-F:\.\d]+),远程:\s{0,100}(?:0+|({src_host}[^,]+)).*?,入站,""",
    """本地:\s{0,100}({src_ip}[a-fA-F:\.\d]+),本地:\s{0,100}(?:0+|({src_host}[^,]+)).*?,出站,""",
    """远程:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),远程:\s{0,100}(?:0+|({dest_host}[^,]+)).*?,出站,""",
    """开始:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """用户:\s{0,100}(({user_fullname}[^,\s]+(\s{1,100}[^,\s]+)+)|({user}[^,]+)),""",
    """域:(?:\s{1,100}|\s{0,100}({domain}[^,]+)),""",
    """应用程序:(?:\s{1,100}|\s{0,100}({process}({directory}(?:[^,]+)?[\\\/])?({process_name}[^\\\/,]+?))),""",
    """CIDS 特征 ID:\s{0,100}({alert_name}\d{1,100}),""",
    """Intrusion ID:\s{0,100}({alert_id}\d{1,100}),""",
    """CIDS 特征字符串:\s{0,100}({alert_type}[^:,]+),""",
    """CIDS 特征字符串:\s{0,100}({alert_name}[^:,]+),""",
    """CIDS 特征字符串:\s{0,100}({alert_type}[^:,]+):\s{0,100}({alert_name}[^,]+)""",
    """入侵 URL:(?:\s{1,100}|\s{0,100}({malware_url}[^,]+)),""",
    """CIDS 特征 ID:\s{0,100}({alert_id}\d{1,100}),""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\w{3}\s{1,100}\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]+)\s""",
    """\s{0,100}({host}[^,]+),SHA-256:""",
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