#### Parser Content
```Java
{
Name = s-mcafee-clean-failed-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "M/d/yyyy\tH:mm:ss a"
    Conditions = [ " (MD5)", " (Clean failed)"]
    Fields = [ 
      """exabeam_host=({host}[\w.\-]+)""",  
      """({time}\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM)+)\t({additional_info}[^\t]+?)\s{0,100}\t(({domain}[^\t]+)(\\)+)?({user}[^\t]+)\t(\w+\[({process_id}\d{1,100})\]|({process}[^\t]+))\t({malware_url}.+?\\({malware_file_name}[^\\]+))\t({alert_name}[^\t]+?)\s{0,100}\(({alert_type}[^\)]+)\)\t({md5}\S+?)\s{0,100}\(MD5\)"""
    ]
    DupFields=[ "host->src_host" ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```