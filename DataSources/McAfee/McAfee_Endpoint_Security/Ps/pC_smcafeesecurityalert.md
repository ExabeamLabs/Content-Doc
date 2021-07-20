#### Parser Content
```Java
{
Name = s-mcafee-security-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """|Executable Fingerprint""", """|4|""" ]
    Fields = [
      """^[^|]{0,2000}\|({time}\d{1,100}\-\d{1,100}\-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
      """exabeam_host=({host}[\w\-.]{1,2000})""",     
      """^([^|]{0,2000}\|){3}({src_host}[^|]{1,2000})\|""",
      """^([^|]{0,2000}\|){4}({src_ip}[a-fA-F0-9.:]{1,2000})""",
      """^([^|]{0,2000}\|){5}(({domain}.+?)\\)?({user}[^\\|]{1,2000})\|""",
      """^([^|]{0,2000}\|){6}({malware_url}.+?\\+({malware_file_name}[^\\|]{1,2000}))\|""",
      """^([^|]{0,2000}\|){11}({alert_type}[^|]{1,2000})\|""",
      """^([^|]{0,2000}\|){12}({alert_type_id}\d{1,100})""",
      """^([^|]{0,2000}\|){13}({alert_name}[^|]{1,2000})\|""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```