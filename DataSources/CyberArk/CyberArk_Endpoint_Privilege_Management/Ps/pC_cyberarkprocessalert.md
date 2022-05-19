#### Parser Content
```Java
{
Name = cyberark-process-alert
    Vendor = CyberArk
    Product = CyberArk Endpoint Privilege Management
    Lms = Splunk
    DataType = "process-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ThreatDetectionAction""", """: Detected""","""Computer""", """PolicyName""", """ProcessCertificateIssuer""", """SourceProcessCertificateIssuer"""]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """PolicyName\s{1,100}:\s{0,100}({alert_name}[^\]]{1,2000}?)\s{1,100}\w+\s{1,100}:""",
      """Computer\s{1,100}:\s{0,100}({host}[^\s]{1,2000})""",
      """SourceProcessCommandLine\s{1,100}:\s{0,100}({parent_process}[^]]{1,2000}?)\s{1,100}\w+\s{1,100}:""",
      """\sProcessCommandLine\s{1,100}:\s{0,100}({command_line}[^]]{1,2000}?)\s{1,100}\w+\s{1,100}:""",
      """FilePath\s{1,100}:\s{0,100}({process}({directory}[^=]{1,2000}\\)([^=]{0,2000}?)?)\s{1,100}\w+\s{1,100}:""",
      """Hash\s{1,100}:\s{0,100}({sha256}\S+)"""
      """FileName\s{1,100}:\s{0,100}({file_name}[^]]{1,2000}?)\s{1,100}\w+\s{1,100}:""",
      """User\s{1,100}:\s{0,100}((?i)eis)?(.\\|\\)?({user}[^\s"]{1,2000})""",
      """PolicyCategory\s{1,100}:\s{0,100}({alert_type}[^]]{1,2000}?)\s{1,100}\w+\s{1,100}:""",
      """FilePath\s{1,100}:\s{0,100}({file_path}[^]]{1,2000}?)\s{1,100}\w+\s{1,100}:"""
    ]
    DupFields = ["host->dest_host","file_name->process_name","file_path->path"]
  

}
```