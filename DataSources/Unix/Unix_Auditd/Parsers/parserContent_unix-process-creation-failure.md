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
      """exe="({process}[^"]*)"""",
      """exe="({process_directory}.+\/)({process_name}.+?)"""",
      """\d\d:\d\d\s+({host}[\w\-.]+)\s+""",
      """\sppid=({parent_process_id}.+?)\s+(\w+=|$)""",
      """\spid=({pid}.+?)\s+(\w+=|$)""",
      """\suid=({user_id}.+?)\s+(\w+=|$)""",
      """\sgid=({group_id}.+?)\s+(\w+=|$)""",
      """\sauid=({account_used_id}.+?)\s+(\w+=|$)""",
      """\sses=({session_id}\d+)\s+(\w+=|$)""",
      """\stype=({activity_type}.+?)\s+(\w+=|$)"""
    ]
        DupFields=[ "host->dest_host", "process_directory->directory" ]
  }
```