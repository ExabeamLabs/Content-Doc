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
    """time"+:"+({time}[^"]+)""",
    """hostname"+:"+({host}[^"]+)""",
    """actor_secondary"+:"+({account}[^"]+)""",
    """actor_primary"+:"+({user}[^"]+)""",
    """audit_name"+:"+({user}[^"]+)""",
    """audit_id"+:"+({audit_id}[\d]+)""",
    """"pid"+:"+({pid}[^"]+)""",
    """"ppid"+:"+({parent_process_id}[^"]+)""",
    """title"+:"+({command_line}[^"]+)""",
    """result"+:"+({outcome}[^"]+)""",
    """event_type"+:"+({activity_type}[^"]+)""",
    """application"+:"+({app}[^"]+)""",
    """category"+:"+({category}[^"]+)""",
    """syscall"+:"+({syscall}[^"]+)""",
    """effective_group_id"+:"+({group_id}[^"]+)""",
    """tags"+:"+\[({tags}[^"]+)\]""",
    """os"+:"+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|Ubuntu)""",
	]
}

{
  Name = s-infoblox-dhcp-3
  Vendor = Infoblox
  Product = Infoblox
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ dhcpd[""", """: received a REQUEST DHCP packet from """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """ ({host}\S+) \S+ dhcpd\[""",
    """REQUEST DHCP packet from relay-agent ({dest_interface}\S+) with """,
    """ for ({dest_ip}[A-Fa-f:\d.]+) \(({dest_mac}\S+)\)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```