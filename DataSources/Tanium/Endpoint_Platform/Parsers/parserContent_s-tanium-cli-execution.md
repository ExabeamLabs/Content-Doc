#### Parser Content
```Java
{
Name = s-tanium-cli-execution
    Vendor = Tanium
    Product = Endpoint Platform
    Lms = Splunk
    DataType = "process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Conditions = [ """exabeam_sourcetype=tanium:cli_execution_log""" ]
    Fields = [
      """({activity_type}cli_execution)""",
      """exabeam_raw="\s{0,100}({host}[\w\.-]{1,2000})\s{0,100}",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]{1,2000}?,|\s{0,100}
```