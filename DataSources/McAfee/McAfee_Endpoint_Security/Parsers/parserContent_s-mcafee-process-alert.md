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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w.\-]+)""",
      """({time}\d{1,100}\/\d{1,100}\/\d{1,100}\t\d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))\t({alert_name}[^\t]+?)\s{0,100}\t(({domain}[^\\]+)\\)?({user}[^\\]+)\s{0,100}\t({process}({directory}[^\t]+?)({process_name}[^\\\t]+))\s{0,100}\t""",
      """\t({alert_type}[^\t]+?)\s{0,100}$""",
    ]
    DupFields = [ "host->dest_host","directory->process_directory" ]
  }
```