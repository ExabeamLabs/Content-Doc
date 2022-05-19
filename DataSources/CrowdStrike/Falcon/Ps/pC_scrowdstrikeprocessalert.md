#### Parser Content
```Java
{
Name = s-crowdstrike-process-alert
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """"eventType":""", """"DetectionSummaryEvent"""", """"DetectName":""", """"Suspicious Activity"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"DetectName":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"DetectDescription":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"Severity":\s{0,100}({alert_severity}[^",]{1,2000})""",
    """"DetectId":\s{0,100}"({alert_id}[^"]{1,2000})"""",
    """({additional_info_1}"DocumentsAccessed":\s{0,100}[^\]]{1,2000}\]).*?({additional_info_2}"ExecutablesWritten":\s{0,100}[^\]]{1,2000}\])""",
    """"CommandLine":"({process}({directory}[^\s]{1,2000})\\\\({process_name}[^\s]{1,2000}))""",
    """"CommandLine":"\\"({process}({directory}[^"]{1,2000}?)\\{1,2}({process_name}[^\\"]{1,2000}))\\"""",
    """"FileName":\s{0,100}"({process_name}[^"]{1,2000})"""",
    """"FilePath":\s{0,100}"({file_path}[^"]{1,2000})"""",
    """"CommandLine"{1,20}:\s{0,100}"{1,20}\\{0,25}"{0,20}({command_line}[^\n]{1,2000}?)\\{0,25}\s{0,100}"{1,20

}
```