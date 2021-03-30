#### Parser Content
```Java
{
Name = cds-process-creation
  Vendor = Unix
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """type=SYSCALL""", """ uid=""", """syscall=""" , """ exe=""""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exe="({process}[^"]*)"""",
    """\suid=({user_id}.+?)\s+(\w+=|$)""",
    """\stype=({activity_type}.+?)\s+(\w+=|$)""",
    """\w+ \d\d \d\d:\d\d:\d\d\s+({host}[\w\-.]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+({host}[\w\-.]+)""",
    """\sppid=({parent_process_id}.+?)\s+(\w+=|$)""",
    """\sexe="({process_directory}.+\/)({process_name}.+?)"""",
    """\spid=({pid}.+?)\s+(\w+=|$)""",
    """\sgid=({group_id}.+?)\s+(\w+=|$)""",
    """\sauid=({account_used_id}.+?)\s+(\w+=|$)"""
 ]
 DupFields = [ "process_directory->directory", "host->dest_host" ]
}
```