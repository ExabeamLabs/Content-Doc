#### Parser Content
```Java
{
Name = unix-process-creation-failure
    Vendor = Unix
    Product = Unix Auditd
    Lms = Splunk
    DataType = "process-created-failed"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = [ """type=SYSCALL""", """success=no""", """msg=audit""", """audispd:""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
      """exe="({process}[^"]{0,2000})"""",
      """exe="({process_directory}.+\/)({process_name}.+?)"""",
      """\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}""",
      """\sppid=({parent_process_id}.+?)\s{1,100}(\w+=|$)""",
      """\spid=({pid}.+?)\s{1,100}(\w+=|$)""",
      """\suid=({user_id}.+?)\s{1,100}(\w+=|$)""",
      """\sgid=({group_id}.+?)\s{1,100}(\w+=|$)""",
      """\sauid=({account_used_id}.+?)\s{1,100}(\w+=|$)""",
      """\sses=({session_id}\d{1,100})\s{1,100}(\w+=|$)""",
      """\stype=({activity_type}.+?)\s{1,100}(\w+=|$)"""
    ]
        DupFields=[ "host->dest_host", "process_directory->directory" ]
  }
```