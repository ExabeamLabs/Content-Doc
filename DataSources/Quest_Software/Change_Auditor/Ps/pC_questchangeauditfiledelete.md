#### Parser Content
```Java
{
Name = quest-change-audit-file-delete
	DataType = "file-operations"
	Conditions = [ """"action": "Delete Object"""", """"folderPath": """", """"timeDetected": """" ]

quest-change-auditor-file-activity = {
    Vendor = Quest Software
    Product = Change Auditor
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """"timeDetected": "({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""""
      """"severity": "({alert_severity}[^"]{1,2000}?)""""
      """"result": "({outcome}[^"]{1,2000}?)""""
      """"event": "({action}[^"]{1,2000}?)""""
      """"user": "({user}[^"]{1,2000}?)""""
      """"userMail": "({user_email}[^@"]{1,2000}?@[^"\.]{1,2000}?\.[^"]{1,2000}?)""""
      """"userSid": "({user_sid}[^"]{1,2000}?)""""
      """"originIPv4": "({dest_ip}[^"]{1,2000}?)""""
      """"computer": "({dest_host}[^"]{1,2000}?)""""
      """"domain": "({domain}[^"]{1,2000}?)""""
      """"folderPath": "({file_path}[^"]{1,2000}?)""""
      """"fileName": "[^"]{1,2000}?\.({file_ext}[^"]{1,2000}?)"""" 
      """"fileName": "({file_name}[^"]{1,2000}?)""""
      """"description": "({additional_info}[^"]{1,2000}?)""""
      """"event": "(EMC )?(File|Folder) ({accesses}(opened|deleted|moved|renamed|created|contents written))"""
      """"action": "({accesses}(Delete|Move|Rename|Add)) Object""""
    ]
    DupFields = ["file_path->file_parent"
}
```