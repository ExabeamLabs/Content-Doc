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
      """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
      """({time}\d+\/\d+\/\d+\t\d+:\d+:\d+ (am|AM|pm|PM))\t({alert_name}[^\t]+?)\s*\t(({domain}[^\\]+)\\)?({user}[^\\]+)\s*\t({process}({directory}[^\t]+?)({process_name}[^\\\t]+))\s*\t""",
      """\t({alert_type}[^\t]+?)\s*$""",
    ]
    DupFields = [ "host->dest_host","directory->process_directory" ]
  }
```