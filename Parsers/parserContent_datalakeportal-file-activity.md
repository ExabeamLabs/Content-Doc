#### Parser Content
```Java
{
Name = datalakeportal-file-activity
  Vendor = DatalakePortal
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyyMMdd'\t'HH:mm:ss"
  Conditions = [ """bdp_datalakeportal_audit""", """<custom_condition_cont-7495>""" ]
  Fields = [
    """({time}2\d{7}\s+\d\d:\d\d:\d\d)\s+\d\d:\d\d:\d\d(\s+\S+){4}\s+({user}\S+)\s+({operation_code}\d+)"""
    """datalakeportal\s+(({operation}[^\s\(]+?)\(({file_id}[^\s\)]+?)\)|({=operation}\w+))\t[^\t]+?\t({file_name}[^\t]+?(\.({file_ext}\.[^\.\t]+))?)\t({bytes}\d+)\t({command_line}[^\t]+)"""

  ]
  DupFields = [ "file_name->object", "operation->accesses" ]
}
```