#### Parser Content
```Java
{
Name = s-mcafee-cleaned-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "M/d/yyyy\tH:mm:ss a"
    Conditions = [ " (MD5)", "\tCleaned"]
    Fields = [ 
      """exabeam_host=({host}[\w.\-]{1,2000})""",  
      """({time}\d{1,100}/\d{1,100}/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM)+)\t({additional_info}[^\t]{1,2000}?)\s{0,100}\t(({domain}[^\t]{1,2000})(\\)+)?({user}[^\t]{1,2000})\t({process}[^\t]{1,2000})\t({malware_url}.+?\\({malware_file_name}[^\\]{1,2000}))\t({alert_name}[^\t]{1,2000}?)\s{0,100}\(({alert_type}[^\)]{1,2000})\)\t({md5}\S+?)\s{0,100}\(MD5\)"""
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