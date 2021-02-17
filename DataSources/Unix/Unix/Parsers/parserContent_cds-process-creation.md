#### Parser Content
```Java
{
Name = cds-process-creation
  Vendor = Unix
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """type=SYSCALL""", """ uid=""", """syscall=""" , """ exe="""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\suid=({user_id}.+?)\s+(\w+=|$)""",
    """\stype=({activity_type}.+?)\s+(\w+=|$)""",
    """\w+ \d\d \d\d:\d\d:\d\d\s+({host}[\w\-.]+)""",
    """({host}[\w.\-]+)\s+audispd:""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+({host}[\w\-.]+)""",
    """\sppid=({parent_process_id}.+?)\s+(\w+=|$)""",
    """\sexe="({command_line}[^"]+)"""",
    """\sexe="({process}(({process_directory}[^"]*?/+))?({process_name}[^"\/]+))"""",
    """\spid=({pid}.+?)\s+(\w+=|$)""",
    """\sgid=({group_id}.+?)\s+(\w+=|$)""",
    """\sauid=({account_used_id}.+?)\s+(\w+=|$)""",
    """\skey="({object}[^"]+)""",
    """\smsg=audit\(({command_id}\d+\.\d+)""",
    """\ssuccess=(|({outcome}.+?))(\s+\w+=|\s*$)""",
 ]
 DupFields = [ "process_directory->directory", "host->dest_host" ]
}
```