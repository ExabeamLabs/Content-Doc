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
      """exabeam_raw="\s*({host}[\w\.-]+)\s*",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]+?,|\s*,))"({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}(?:\+|-)\d\d:\d\d)",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]+?,|\s*,)){4}"({path}(({directory}[^"]+)[\\/])?({process_name}.+?))",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]+?,|\s*,)){5}"({command_line}.+?)",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]+?,|\s*,)){6}"({md5}[\da-fA-F]+)",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]+?,|\s*,)){7}"\s*({domain}.+?)\s*",""",
      """exabeam_raw=(?:(?:'',|"",|'.+?',|".+?",|[^",]+?,|\s*,)){8}"\s*({user}.+?)\s*",""",
    ]
    DupFields = [ "host->dest_host","path->process","directory->process_directory" ]
  }
```