#### Parser Content
```Java
{
Name = leef-beyondtrust-app-activity-4
Vendor = BeyondTrust
Product = BeyondInsight
Lms = Direct
DataType = "app-activity"
TimeFormat = "MMM dd yyyy HH:mm:ss"
Conditions = [ """cat=Change""", """LEEF:""", """|BeyondTrust|BeyondInsight|""", """EventDesc=False  password change failed at azure logon  Authentication Error: Password has expired""" ]
Fields = [
"""devTime=({time}\w{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2})\s{0,100}"""
"""EventDesc=({event_name}[^=]{1,2000}?)\s{1,20}(\w+=|")"""
"""dst=({dest_ip}[a-fA-F:\d.]{1,2000})"""
"""({app}BeyondInsight)"""
"""src=({src_ip}[a-fA-F:\d.]{1,2000})"""
"""\sAccountName =(-|({user_email}[^@"\s]{1,2000}@([^@"\s]{1,2000})))"""
"""\sAccountName =(-|([^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^\s]{1,2000}?)[\\]{1,20})?({user}[\w.-]{1,2000}))"""
"""EventName =({activity}[^\s]{1,2000}?)\s"""
"""Authentication Error:\s{0,100}({failure_reason}[^=]{1,2000})\s\w+"""
]


}
```