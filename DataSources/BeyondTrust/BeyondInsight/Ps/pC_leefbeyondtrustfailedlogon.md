#### Parser Content
```Java
{
Name = leef-beyondtrust-failed-logon
Vendor = BeyondTrust
Product = BeyondInsight
Lms = Direct
DataType = "failed-logon"
TimeFormat = "MMM dd yyyy HH:mm:ss"
Conditions = [ """cat=Direct Connect Failure""", """LEEF:""", """|BeyondTrust|BeyondInsight|""" ]
Fields = [
"""devTime=({time}\w{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2})\s{0,100}"""
"""IPAddress=({src_ip}[a-fA-F:\d.]{1,2000})"""
"""ClientIPAddress=({dest_ip}[a-fA-F:\d.]{1,2000})"""
"""Message=({failure_reason}[^\s]+)\s"""
"""HostName =({host}[\w.-]{1,1000})\t{0,100}"""
"""\sUserName =(-|({user_email}[^@"\s]{1,2000}@([^@"\s]{1,2000})))"""
"""\sUserName =(-|([^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^\s]{1,2000}?)[\\]{1,20})?({user}[\w.-]{1,2000}))"""
"""({app}BeyondInsight)"""
]


}
```