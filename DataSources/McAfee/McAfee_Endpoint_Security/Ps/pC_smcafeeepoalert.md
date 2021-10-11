#### Parser Content
```Java
{
Name = s-mcafee-epo-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "_timestamp=", "signature_id", "threat_handled", "is_laptop" ]
    Fields = [
      """detected_timestamp="{0,20}\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """AutoID="{0,20}({alert_id}\d{1,100})""",
      """event_id="{0,20}({alert_id}\d{1,100})""",
      """signature="{0,20}\s{0,100}(_|({alert_name}.+?))\s{0,100}"{0,20},? threat_type""",
      """signature="{0,20}\s{0,100}(_|({alert_type}.+?))\s{0,100}"{0,20},? threat_type""",
      """threat_type="{0,20}(\s|none|({alert_type}.+?))"{0,20},? signature_id""",
      """signature_id="{0,20}({signature_id}\d{1,100})""",
      """severity_id="{0,20}({alert_severity}\d{1,100})""",
      """event_description="{0,20}({additional_info}[^"]{1,2000})""",
      """file_name="{0,20}(\s|({malware_url}[^"]{1,2000}))"""",
      """\slogon_user="{0,20}([^\\]{1,2000}\\+)?({user}.+?)"{1,20}""",
      """C:\\Users\\({user}[^\\]{1,2000})""",
      """, user="{1,20}(N\/A|NULL|({user}[^,]{1,2000}?))(|,.*?)"{1,20},""",
      """dest_nt_host="{0,20}({src_host}[^\s"]{1,2000})""",
      """dest_ip="{0,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_url->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```