#### Parser Content
```Java
{
Name = s-crowdstrike-security-alert
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """"eventType":""", """"DetectionSummaryEvent"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"DetectName":\s{0,100}"({alert_type}[^"]+)""",
    """"Technique":"({alert_name}[^"]+)"""",
    """"Severity":\s{0,100}({alert_severity}[^",]+)""",
    """"DetectId":\s{0,100}"({alert_id}[^"]+)""",
    """({additional_info_1}"DocumentsAccessed":\s{0,100}[^\]]+\]).*?({additional_info_2}"ExecutablesWritten":\s{0,100}[^\]]+\])""",
    """"FileName":\s{0,100}"(|({process_name}[^"]+))"""",
    """"FilePath":\s{0,100}"(|({file_path}[^"]+))"""",
    """"CommandLine"{1,20}:\s{0,100}"{1,20}\\*"{0,20}({command_line}.+?)\\*\s{0,100}"{1,20}
```