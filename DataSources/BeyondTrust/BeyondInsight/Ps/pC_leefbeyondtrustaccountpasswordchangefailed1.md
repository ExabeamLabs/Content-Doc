#### Parser Content
```Java
{
Name = leef-beyondtrust-account-password-change-failed-1
Vendor = BeyondTrust
Product = BeyondInsight
Lms = Direct
DataType = "password-change"
TimeFormat = "MMM dd yyyy HH:mm:ss"
Conditions = [ """cat=Change""", """LEEF:""", """|BeyondTrust|BeyondInsight|""", """EventDesc=Password change failed""" ]
Fields = [
"""devTime=({time}\w{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2})\s{0,100}"""
"""EventDesc=({event_name}[^.]{1,2000})\.\s*[^=]+"""
"""dst=({dest_ip}[a-fA-F:\d.]{1,2000})"""
"""({app}BeyondInsight)"""
"""src=({src_ip}[a-fA-F:\d.]{1,2000})"""
"""\sAccountName =(-|({user_email}[^@"\s]{1,2000}@([^@"\s]{1,2000})))"""
"""\sAccountName =(-|([^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^\s]{1,2000}?)[\\]{1,20})?({user}[\w.-]{1,2000}))"""
"""EventName =({activity}[^\s]{1,2000}?)\s"""
]


}
```