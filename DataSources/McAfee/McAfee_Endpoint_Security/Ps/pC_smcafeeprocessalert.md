#### Parser Content
```Java
{
Name = s-mcafee-process-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "process-alert"
    IsHVF = true
    TimeFormat = "MM/dd/yyyy\thh:mm:ss a"
    Conditions = [ "\tAction blocked","\tWould be blocked by Access Protection rule " ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
      """({time}\d{1,100}\/\d{1,100}\/\d{1,100}\t\d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))\t({alert_name}[^\t]{1,2000}?)\s{0,100}\t(({domain}[^\\]{1,2000})\\)?({user}[^\\]{1,2000})\s{0,100}\t({process}({directory}[^\t]{1,2000}?)({process_name}[^\\\t]{1,2000}))\s{0,100}\t""",
      """\t({alert_type}[^\t]{1,2000}?)\s{0,100}$""",
    ]
    DupFields = [ "host->dest_host","directory->process_directory" ]
  }
```