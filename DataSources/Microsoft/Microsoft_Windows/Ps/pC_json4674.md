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
	""""Hostname"{0,20}:"{0,20}({host}[^"]{1,2000})""",
	"""EventType"{0,20}:"{0,20}({outcome}[^"]{1,2000})""",
	"""ProcessName"{0,20}:"{0,20}(?: |({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/";]{1,2000}?)))\s{0,100}"""",
	""""SubjectUserSid"{0,20}:"{0,20}(SYSTEM|({user_sid}[^"]{1,2000}))""",
	""""SubjectUserName"{0,20}:"{0,20}(SYSTEM|({user}[^"]{1,2000}))""",
	""""SubjectDomainName"{0,20}:"{0,20}({domain}[^"]{1,2000})""",
	""""SubjectLogonId"{0,20}:"{0,20}({logon_id}[^"]{1,2000})""",
	""""ProcessID"{0,20}:({process_id}[^,"]{1,2000})""",
	""""HandleId"{0,20}:"{0,20}({object_id}[^"]{1,2000})""",
	""""ObjectType"{0,20}:"{0,20}(-|({object_type}[^"]{1,2000}))""",
	""""ObjectName"{0,20}:"{0,20}(-|({object}[^"]{1,2000}))""",
	""""ObjectServer":"(-|({object_server}[^\s"]{1,2000}))""",
	"""AccessMask"{0,20}:"{0,20}(-|({accesses}[^"]{1,2000}))""",
	"""PrivilegeList"{0,20}:"{0,20}(-|({privileges}[^"]{1,2000}))""",
        """"Category"{0,20}:"{0,20}({category}[^"]{1,2000})""",
	""""Opcode"{0,20}:"{0,20}({severity}[^"]{1,2000})""",
	]
   }
```