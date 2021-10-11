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
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]{1,2000}?,|\s{0,100},))"({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}(?:\+|-)\d\d:\d\d)",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]{1,2000}?,|\s{0,100},)){4}"({path}(({directory}[^"]{1,2000})[\\/])?({process_name}.+?))",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]{1,2000}?,|\s{0,100},)){5}"({command_line}.+?)",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]{1,2000}?,|\s{0,100},)){6}"({md5}[\da-fA-F]{1,2000})",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]{1,2000}?,|\s{0,100},)){7}"\s{0,100}({domain}.+?)\s{0,100}",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]{1,2000}?,|\s{0,100},)){8}"\s{0,100}({user}.+?)\s{0,100}",""",
    ]
    DupFields = [ "host->dest_host","path->process","directory->process_directory" ]
  }
```