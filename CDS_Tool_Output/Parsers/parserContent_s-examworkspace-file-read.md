#### Parser Content
```Java
{
Name = s-examworkspace-file-read
  Vendor = ExamWorkspace
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ACTN_TYPE="R"""", """EXAM_ID=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """USER_FULL_NM="({user_fullname}[^"]+)"""",
    """USER_NM="({user}[^"]+)"""",
    """DCMNT_FILE_NM="({file_name}[^"]+?(\.({file_ext}[^\."]+))?)"""",
    """UPDT_TS="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```