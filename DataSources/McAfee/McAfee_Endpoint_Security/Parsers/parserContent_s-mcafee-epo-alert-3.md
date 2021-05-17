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
      """signature="({alert_name}[^"]{1,2000})"""",
      """signature_id="({signature_id}[^"]{1,2000})"""",
      """category="({threat_category}[^"]{1,2000})"""",
      """AnalyzerHostName="({host}[^"]{1,2000})"""",
      """severity_id="({alert_severity}\d{1,100})"""",
      """SourceIPV4="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """TargetIPV4="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """threat_type="({alert_type}[^"]{1,2000})"""",
      """file_name="{0,20}(\s{0,100}|({malware_url}[^"]{1,2000}?))"""",
      """ Name="({additional_info}[^"]{1,2000})"""",
      """domain_name="({domain}[^"]{1,2000})"""",
      """user_name="{0,20}(N\/A|\s{1,100}|NULL|([^\\]{1,2000}\\+)?({user}[^\s,"]{1,2000}))"""",
      """AutoID="({alert_id}[^"]{1,2000})"""",
      """TargetProcessName="({process_name}[^"]{1,2000})"""",
      """target_process_parent_name="({parent_process}[^"]{1,2000})"""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "malware_url->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```