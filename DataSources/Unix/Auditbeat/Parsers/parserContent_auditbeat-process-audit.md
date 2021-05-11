#### Parser Content
```Java
{
Name = auditbeat-process-audit
  Vendor = Unix
  Product = Auditbeat
  Lms = Direct
  DataType = "app-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = ["""changed-identity-of""","""process""","""audit_id"""]
  Fields = [
    """time"{1,20}:"{1,20}({time}[^"]+)""",
    """hostname"{1,20}:"{1,20}({host}[^"]+)""",
    """actor_secondary"{1,20}:"{1,20}({account}[^"]+)""",
    """actor_primary"{1,20}:"{1,20}({user}[^"]+)""",
    """audit_name"{1,20}:"{1,20}({user}[^"]+)""",
    """audit_id"{1,20}:"{1,20}({audit_id}[\d]+)""",
    """"pid"{1,20}:"{1,20}({pid}[^"]+)""",
    """"ppid"{1,20}:"{1,20}({parent_process_id}[^"]+)""",
    """title"{1,20}:"{1,20}({command_line}[^"]+)""",
    """result"{1,20}:"{1,20}({outcome}[^"]+)""",
    """event_type"{1,20}:"{1,20}({activity_type}[^"]+)""",
    """application"{1,20}:"{1,20}({app}[^"]+)""",
    """category"{1,20}:"{1,20}({category}[^"]+)""",
    """syscall"{1,20}:"{1,20}({syscall}[^"]+)""",
    """effective_group_id"{1,20}:"{1,20}({group_id}[^"]+)""",
    """tags"{1,20}:"{1,20}\[({tags}[^"]+)\]""",
    """os"{1,20}:"{1,20}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|Ubuntu)""",
	]
}
```