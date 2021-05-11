#### Parser Content
```Java
{
Name = cds-process-creation
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """type=SYSCALL""", """ uid=""", """syscall=""" , """ exe="""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\suid=({user_id}.+?)\s{1,100}(\w+=|$)""",
    """\stype=({activity_type}.+?)\s{1,100}(\w+=|$)""",
    """\w+ \d\d \d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]+)""",
    """({host}[\w.\-]+)\s{1,100}audispd:""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s{1,100}({host}[\w\-.]+)""",
    """\sppid=({parent_process_id}.+?)\s{1,100}(\w+=|$)""",
    """\sexe="({command_line}[^"]+)"""",
    """\sexe="({process}(({process_directory}[^"]*?/+))?({process_name}[^"\/]+))"""",
    """\spid=({pid}.+?)\s{1,100}(\w+=|$)""",
    """\sgid=({group_id}.+?)\s{1,100}(\w+=|$)""",
    """\sauid=({account_used_id}.+?)\s{1,100}(\w+=|$)""",
    """\skey="({object}[^"]+)""",
    """\smsg=audit\(({command_id}\d{1,100}\.\d{1,100})""",
    """\ssuccess=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
 ]
 DupFields = [ "process_directory->directory", "host->dest_host" ]
}
```