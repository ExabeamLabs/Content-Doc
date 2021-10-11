#### Parser Content
```Java
{
Name = syslog-mcafee-epo-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd H:mm:ss a"
    Conditions = [ """ McAfee ePolicy Orchestrator ""","""ePOEvents""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d{1,2}:\d\d:\d\d (AM|PM|am|pm))(,[^,]{0,2000}){5}ePOEvents""",
      """ePOEvents([^,]{0,2000},){13}["']{0,2000}({host}[\w\-.]{1,2000})""",
      """ePOEvents([^,]{0,2000},){33,34}["']{0,2000}(({domain}[^\\\/"',]{1,2000}?)\\)?({user}[^\\\/\s"',.]{1,2000})""",
      """ePOEvents([^,]{0,2000},){36}["']{0,2000}({threat_category}[^"',]{1,2000})""",
      """ePOEvents([^,]{0,2000},){46}["']{0,2000}({alert_severity}[^"',]{1,2000})""",
      """ePOEvents([^,]{0,2000},){2}["']{0,2000}({alert_name}[^"',]{1,2000})""",
      """ePOEvents([^,]{0,2000},){1}["']{0,2000}({alert_type}[^"',]{1,2000})""",
      """ePOEvents([^,]{0,2000},){42}["']{0,2000}(file:\/+)?({malware_url}[^"',]{1,2000})""",
      """ePOEvents([^,]{0,2000},){41}["']{0,2000}(none|({additional_info}[^"',]{1,2000}))""",
      """ePOEvents([^,]{0,2000},){43}["']{0,2000}(none|({process}[^"',]{1,2000}\\({process_name}[^"',]{1,2000})))"""
    ]
    DupFields = [ "host->src_host" ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->description"]
      NameTemplate = """McAfee Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```