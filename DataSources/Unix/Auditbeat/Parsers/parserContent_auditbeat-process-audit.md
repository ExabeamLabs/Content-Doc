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
    """time"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """hostname"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """actor_secondary"{1,20}:"{1,20}({account}[^"]{1,2000})""",
    """actor_primary"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """audit_name"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """audit_id"{1,20}:"{1,20}({audit_id}[\d]{1,2000})""",
    """"pid"{1,20}:"{1,20}({pid}[^"]{1,2000})""",
    """"ppid"{1,20}:"{1,20}({parent_process_id}[^"]{1,2000})""",
    """title"{1,20}:"{1,20}({command_line}[^"]{1,2000})""",
    """result"{1,20}:"{1,20}({outcome}[^"]{1,2000})""",
    """event_type"{1,20}:"{1,20}({activity_type}[^"]{1,2000})""",
    """application"{1,20}:"{1,20}({app}[^"]{1,2000})""",
    """category"{1,20}:"{1,20}({category}[^"]{1,2000})""",
    """syscall"{1,20}:"{1,20}({syscall}[^"]{1,2000})""",
    """effective_group_id"{1,20}:"{1,20}({group_id}[^"]{1,2000})""",
    """tags"{1,20}:"{1,20}\[({tags}[^"]{1,2000})\]""",
    """os"{1,20}:"{1,20}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|Ubuntu)""",
	]
}
```