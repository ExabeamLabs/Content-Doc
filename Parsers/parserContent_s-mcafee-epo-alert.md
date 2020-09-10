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
      """timestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """(AutoID|event_id)="*({alert_id}\d+)""",
      """signature="*\s*(_|({alert_name}.+?))\s*"*,? threat_type""",
      """signature="*\s*(_|({alert_type}.+?))\s*"*,? threat_type""",
      """threat_type="*(\s|none|({alert_type}.+?))"*,? signature_id""",
      """signature_id="*({signature_id}\d+)""",
      """severity_id="*({alert_severity}\d+)""",
      """event_description="*({additional_info}[^"]+)""",
      """file_name="*(\s*|({malware_url}[^"]+?))"""",
      """\slogon_user.+?user="*(N\/A|\s+|NULL|([^\\]+\\+)?({user}[^\s,"]+))""",
      """\slogon_user="*([^\\]+\\+)?({user}.+?)"*\s+user=(?=N\/A|\s+|NULL)""",
      """C:\\Users\\({user}[^\\]+)""",
      """, user="+(N\/A|NULL|({user}[^,]+?))(|,.*?)"+,""",
      """dest_nt_host="*({src_host}[^\s"]+)""",
      """dest_ip="*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_url->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```