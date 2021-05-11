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
      """({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d{1,2}:\d\d:\d\d (AM|PM|am|pm))(,[^,]*){5}ePOEvents""",
      """ePOEvents([^,]*,){13}["']*({host}[\w\-.]+)""",
      """ePOEvents([^,]*,){33,34}["']*(({domain}[^\\\/"',]+?)\\)?({user}[^\\\/\s"',.]+)""",
      """ePOEvents([^,]*,){36}["']*({threat_category}[^"',]+)""",
      """ePOEvents([^,]*,){46}["']*({alert_severity}[^"',]+)""",
      """ePOEvents([^,]*,){2}["']*({alert_name}[^"',]+)""",
      """ePOEvents([^,]*,){1}["']*({alert_type}[^"',]+)""",
      """ePOEvents([^,]*,){42}["']*(file:\/+)?({malware_url}[^"',]+)""",
      """ePOEvents([^,]*,){41}["']*(none|({additional_info}[^"',]+))""",
      """ePOEvents([^,]*,){43}["']*(none|({process}[^"',]+\\({process_name}[^"',]+)))"""
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