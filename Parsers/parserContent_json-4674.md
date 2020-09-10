#### Parser Content
```Java
{
Name = json-4674
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [""""EventID":4674""","An operation was attempted on a privileged object"]
    Fields = [
	""""EventTime"*:"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
	""""EventID"*:({event_code}\d+)""",
	"""({event_name}An operation was attempted on a privileged object)""",
	""""Hostname"*:"*({host}[^"]+)""",
	"""EventType"*:"*({outcome}[^"]+)""",
	"""ProcessName"*:"*(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s*"""",
	""""SubjectUserSid"*:"*(SYSTEM|({user_sid}[^"]+))""",
	""""SubjectUserName"*:"*(SYSTEM|({user}[^"]+))""",
	""""SubjectDomainName"*:"*({domain}[^"]+)""",
	""""SubjectLogonId"*:"*({logon_id}[^"]+)""",
	""""ProcessID"*:({process_id}[^,"]+)""",
	""""HandleId"*:"*({object_id}[^"]+)""",
	""""ObjectType"*:"*(-|({object_type}[^"]+))""",
	""""ObjectName"*:"*(-|({object}[^"]+))""",
	""""ObjectServer":"(-|({object_server}[^\s"]+))""",
	"""AccessMask"*:"*(-|({accesses}[^"]+))""",
	"""PrivilegeList"*:"*(-|({privileges}[^"]+))""",
        """"Category"*:"*({category}[^"]+)""",
	""""Opcode"*:"*({severity}[^"]+)""",
	]
   }
```