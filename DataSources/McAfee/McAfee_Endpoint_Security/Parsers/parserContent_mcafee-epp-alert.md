#### Parser Content
```Java
{
Name = mcafee-epp-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = RsaSa
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["%ePolicy-", "VIRUSCAN" ]
    Fields = [
      """({alert_id}[^\s\^]+)[\s\^]+({host}[^\^\s]+)[\s\^]+({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}).+?({alert_type}(?:hip|av|fw)\.\w+)[\s\^]+\d{1,100}[\s\^]+\d{1,100}[\s\^]+({alert_name}BO\:(Stack|Writable BO:Heap|Image|Memory)|[^\:\^]+)""",
      """VIRUSCAN\d{1,100}[\s\^]+VirusScan Enterprise[\s\^]+\d{1,100}\.\d{1,100}[\s\^]+({src_host}[^\s\^]+)[\s\^]+(?:(?!\(null\))({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?""",
      """(?:OAS|ODS)(?:[\^\s]+[^\^\s]+){4}[\s\^]+(?:[\s\w]+\\)?({user}[^\^\s]+)"""
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "src_host->malwareVictimHost", "alert_type->malwareCategory"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```