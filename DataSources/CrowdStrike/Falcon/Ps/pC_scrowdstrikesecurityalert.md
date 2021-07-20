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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"DetectName":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"Technique":"({alert_name}[^"]{1,2000})"""",
    """"Severity":\s{0,100}({alert_severity}[^",]{1,2000})""",
    """"DetectId":\s{0,100}"({alert_id}[^"]{1,2000})""",
    """({additional_info_1}"DocumentsAccessed":\s{0,100}[^\]]{1,2000}\]).*?({additional_info_2}"ExecutablesWritten":\s{0,100}[^\]]{1,2000}\])""",
    """"FileName":\s{0,100}"(|({process_name}[^"]{1,2000}))"""",
    """"FilePath":\s{0,100}"(|({file_path}[^"]{1,2000}))"""",
    """"CommandLine"{1,20}:\s{0,100}"{1,20}\\{0,25}"{0,20}({command_line}[^\n]{1,2000}?)\\{0,25}\s{0,100}"{1,20}
```