#### Parser Content
```Java
{
Name = s-mcafee-epo-alert-3
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "_timestamp=", "signature_id", "threat_handled", "is_laptop", "SourceIPV4=", "detected_timestamp=", """product="McAfee Endpoint Security"""" ]
    Fields = [
      """detected_timestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """signature="({alert_name}[^"]+)"""",
      """signature_id="({signature_id}[^"]+)"""",
      """category="({threat_category}[^"]+)"""",
      """AnalyzerHostName="({host}[^"]+)"""",
      """severity_id="({alert_severity}\d+)"""",
      """SourceIPV4="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """TargetIPV4="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """threat_type="({alert_type}[^"]+)"""",
      """file_name="*(\s*|({malware_url}[^"]+?))"""",
      """ Name="({additional_info}[^"]+)"""",
      """domain_name="({domain}[^"]+)"""",
      """user_name="*(N\/A|\s+|NULL|([^\\]+\\+)?({user}[^\s,"]+))"""",
      """AutoID="({alert_id}[^"]+)"""",
      """TargetProcessName="({process_name}[^"]+)"""",
      """target_process_parent_name="({parent_process}[^"]+)"""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "malware_url->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```