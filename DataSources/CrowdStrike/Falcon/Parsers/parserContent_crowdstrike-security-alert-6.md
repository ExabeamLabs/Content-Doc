#### Parser Content
```Java
{
Name = crowdstrike-security-alert-6
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """"ExternalApiType": "Event_DetectionSummaryEvent"""",  """"Severity"""", """"FalconHostLink""""  ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"ProcessStartTime":\s{0,100}({time}\d{1,100})""",
      """"UserName":\s{0,100}"({user}[^"@]{1,2000})(@({src_host}[^"]{1,2000}))?"""",
      """"ComputerName":\s{0,100}"({src_host}[^"]{1,2000})"""",
      """"DetectName":\s{0,100}"({alert_name}[^"]{1,2000})"""",
      """"ExternalApiType":\s{0,100}"({alert_type}[^"]{1,2000})"""",
      """"DetectDescription":\s{0,100}"({additional_info}[^"]{1,2000})"""",
      """"Severity":\s{0,100}({alert_severity}\d{1,100})""",
      """"SeverityName":\s{0,100}"({alert_severity}[^"]{1,2000}?)"""",
      """"FileName":\s{0,100}"({file_name}[^"]{1,2000}?)"""",
      """"FilePath":\s{0,100}"({file_path}[^"]{1,2000}?)\\?"""",
      """"CommandLine"{1,20}:\s{0,100}"{1,20}\\{0,25}"{0,20}({command_line}[^\n]{1,2000}?)\\{0,25}\s{0,100}"{1,20}
```