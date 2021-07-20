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
      """({alert_id}[^\s\^]{1,2000})[\s\^]{1,2000}({host}[^\^\s]{1,2000})[\s\^]{1,2000}({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}).+?({alert_type}(?:hip|av|fw)\.\w+)[\s\^]{1,2000}\d{1,100}[\s\^]{1,2000}\d{1,100}[\s\^]{1,2000}({alert_name}BO\:(Stack|Writable BO:Heap|Image|Memory)|[^\:\^]{1,2000})""",
      """VIRUSCAN\d{1,100}[\s\^]{1,2000}VirusScan Enterprise[\s\^]{1,2000}\d{1,100}\.\d{1,100}[\s\^]{1,2000}({src_host}[^\s\^]{1,2000})[\s\^]{1,2000}(?:(?!\(null\))({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?""",
      """(?:OAS|ODS)(?:[\^\s]{1,2000}[^\^\s]{1,2000}){4}[\s\^]{1,2000}(?:[\s\w]{1,2000}\\)?({user}[^\^\s]{1,2000})"""
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "src_host->malwareVictimHost", "alert_type->malwareCategory"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```