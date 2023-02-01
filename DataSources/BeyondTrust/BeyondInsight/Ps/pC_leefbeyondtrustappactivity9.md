#### Parser Content
```Java
{
Name = leef-beyondtrust-app-activity-9
Vendor = BeyondTrust
Product = BeyondInsight
Lms = Direct
DataType = "app-activity"
TimeFormat = "MMM dd yyyy HH:mm:ss"
Conditions = [ """cat=PMM Managed Account""", """LEEF:""", """|BeyondTrust|BeyondInsight|""" ]
Fields = [
"""devTime=({time}\w{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2})\s{0,100}"""
"""\sUserName =(-|({user_email}[^@"\s]{1,2000}@([^@"\s]{1,2000})))"""
"""\sUserName =(-|([^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^\s]{1,2000}?)[\\]{1,20})?({user}[\w.-]{1,2000}))"""
"""({app}BeyondInsight)"""
"""IPAddress=({src_ip}[a-fA-F:\d.]{1,2000})"""
"""PasswordHistory=({additional_info}[^=]{1,2000}?)\s{1,20}(\w+=|")"""
]


}
```