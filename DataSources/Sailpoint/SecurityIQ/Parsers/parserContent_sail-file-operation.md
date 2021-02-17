#### Parser Content
```Java
{
Name = sail-file-operation
 Vendor = Sailpoint
 Product = SecurityIQ
 Lms= Direct
 DataType="file-read"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
 Conditions=["""action type\""", """object name\""", """samaccountname\""", """creation_timestamp\""", """application type\""" ]
 Fields=[
   """creation_timestamp\\"+:\\"+({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
   """message"+:\s*"+[^\s]+\s+({host}[^\s]+)""",
   """"+samaccountname\\"+:\\"+({user}[^\\"]+)""",
   """"+userprincipalname\\"+:\\"+({user_email}[^\\"]+)""",
   """"+object name\\"+:\\"+({file_name}[^\\"]+)""",
   """"+file extension\\"+:\\"+({file_extension}[^\\"]+)""",
   """"+ip address\\"+:\\"+({src_ip}[^\\"]+)""",
   """"+domain\\"+:\\"+({domain}[^\\"]+)""",
   """"+application type\\"+:\\"+({app}[^\\"]+)""",
   """"+path\\"+:\\"+\\+({path}[^"]+)\\"+""",
   """"+action type\\"+:\\"+({activity}[^\\"]+)"""
 ]
}
```