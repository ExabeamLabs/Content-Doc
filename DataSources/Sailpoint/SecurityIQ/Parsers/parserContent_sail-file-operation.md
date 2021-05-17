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
   """creation_timestamp\\"{1,20}:\\"{1,20}({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
   """message"{1,20}:\s{0,100}"{1,20}[^\s]{1,2000}\s{1,100}({host}[^\s]{1,2000})""",
   """"{1,20}samaccountname\\"{1,20}:\\"{1,20}({user}[^\\"]{1,2000})""",
   """"{1,20}userprincipalname\\"{1,20}:\\"{1,20}({user_email}[^\\"]{1,2000})""",
   """"{1,20}object name\\"{1,20}:\\"{1,20}({file_name}[^\\"]{1,2000})""",
   """"{1,20}file extension\\"{1,20}:\\"{1,20}({file_extension}[^\\"]{1,2000})""",
   """"{1,20}ip address\\"{1,20}:\\"{1,20}({src_ip}[^\\"]{1,2000})""",
   """"{1,20}domain\\"{1,20}:\\"{1,20}({domain}[^\\"]{1,2000})""",
   """"{1,20}application type\\"{1,20}:\\"{1,20}({app}[^\\"]{1,2000})""",
   """"{1,20}path\\"{1,20}:\\"{1,20}\\+({path}[^"]{1,2000})\\"{1,20}""",
   """"{1,20}action type\\"{1,20}:\\"{1,20}({activity}[^\\"]{1,2000})"""
 ]
}
```