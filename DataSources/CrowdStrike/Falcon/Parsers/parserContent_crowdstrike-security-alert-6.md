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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"ProcessStartTime":\s{0,100}({time}\d{1,100})""",
      """"UserName":\s{0,100}"({user}[^"@]+)(@({src_host}[^"]+))?"""",
      """"ComputerName":\s{0,100}"({src_host}[^"]+)"""",
      """"DetectName":\s{0,100}"({alert_name}[^"]+)"""",
      """"ExternalApiType":\s{0,100}"({alert_type}[^"]+)"""",
      """"DetectDescription":\s{0,100}"({additional_info}[^"]+)"""",
      """"Severity":\s{0,100}({alert_severity}\d{1,100})""",
      """"SeverityName":\s{0,100}"({alert_severity}[^"]+?)"""",
      """"FileName":\s{0,100}"({file_name}[^"]+?)"""",
      """"FilePath":\s{0,100}"({file_path}[^"]+?)\\?"""",
      """"CommandLine"{1,20}:\s{0,100}"{1,20}\\*"{0,20}({command_line}.+?)\\*\s{0,100}"{1,20}
```