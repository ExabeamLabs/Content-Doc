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
	""""EventTime"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
	""""EventID"{0,20}:({event_code}\d{1,100})""",
	"""({event_name}An operation was attempted on a privileged object)""",
	""""Hostname"{0,20}:"{0,20}({host}[^"]+)""",
	"""EventType"{0,20}:"{0,20}({outcome}[^"]+)""",
	"""ProcessName"{0,20}:"{0,20}(?: |({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/";]+?)))\s{0,100}"""",
	""""SubjectUserSid"{0,20}:"{0,20}(SYSTEM|({user_sid}[^"]+))""",
	""""SubjectUserName"{0,20}:"{0,20}(SYSTEM|({user}[^"]+))""",
	""""SubjectDomainName"{0,20}:"{0,20}({domain}[^"]+)""",
	""""SubjectLogonId"{0,20}:"{0,20}({logon_id}[^"]+)""",
	""""ProcessID"{0,20}:({process_id}[^,"]+)""",
	""""HandleId"{0,20}:"{0,20}({object_id}[^"]+)""",
	""""ObjectType"{0,20}:"{0,20}(-|({object_type}[^"]+))""",
	""""ObjectName"{0,20}:"{0,20}(-|({object}[^"]+))""",
	""""ObjectServer":"(-|({object_server}[^\s"]+))""",
	"""AccessMask"{0,20}:"{0,20}(-|({accesses}[^"]+))""",
	"""PrivilegeList"{0,20}:"{0,20}(-|({privileges}[^"]+))""",
        """"Category"{0,20}:"{0,20}({category}[^"]+)""",
	""""Opcode"{0,20}:"{0,20}({severity}[^"]+)""",
	]
   }
```